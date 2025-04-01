'use strict';

const Node = require('../node');
const crypto = require('crypto');

// Message types
const MSG_TYPES = {
    EVENT: 'babble-event',
    SYNC_REQUEST: 'babble-sync-request',
    SYNC_RESPONSE: 'babble-sync-response',
    BLOCK: 'babble-block',
    BLOCK_SIGNATURE: 'babble-block-signature'
};

// Helper function to calculate hash with proper cryptographic function
function calculateHash(data) {
    return crypto.createHash('sha256').update(typeof data === 'string' ? data : JSON.stringify(data)).digest('hex');
}

/**
 * LibP2PBabbleNode implements a node in the Hashgraph consensus system
 * using a two-layer architecture:
 * 1. Network layer: handles message transmission via BFT simulator's network interface
 * 2. Consensus layer: implements the Hashgraph consensus algorithm
 */
class LibP2PBabbleNode extends Node {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent);

        // Store the config
        this.config = customConfig || {};

        // Byzantine fault tolerance parameters
        this.f = Math.floor((this.nodeNum - 1) / 3); // Max fault tolerance

        // Node properties
        this.isByzantine = false;
        this.byzantineType = "none";

        // Hashgraph data structures
        this.events = {};              // Hash -> Event
        this.head = null;              // Latest event created by this node
        this.witnesses = {};           // Round -> Witness events
        this.pendingEvents = [];       // Events to be processed
        this.knownEvents = {};         // NodeID -> Latest event from that node
        this.receivedEvents = new Set(); // To track received events

        // Consensus and block related
        this.round = 0;                 // Current consensus round
        this.blocks = [];               // Ordered blocks
        this.pendingTransactions = [];  // Transactions waiting to be included in events
        this.consensusEvents = new Set(); // Events that reached consensus
        this.blockSignatures = {};      // BlockHash -> Signatures
        this.processedBlocks = new Set(); // To prevent duplicate processing

        // Timing and synchronization
        this.syncInterval = this.config.babble?.syncInterval || 1000;
        this.lastSyncTime = {};        // NodeID -> Last sync time
        this.heartbeatTimeout = this.config.lambda || 3;
        this.isDecided = false;        // Whether consensus has been reached
        this.isSuspended = false;      // Whether consensus is suspended
        this.undeterminedEvents = 0;   // Counter for events without determined order
        this.lastEventCreationTime = 0; // To rate limit event creation

        // Statistics and debugging
        this.msgCount = { sent: 0, received: 0 };
        this.eventCount = { created: 0, received: 0, processed: 0 };
        this.syncCount = { requests: 0, responses: 0 };

        // Initialize the node
        this.initialize();
    }

    // Initialize the node
    initialize() {
        this.logger.info(['Initializing LibP2P-Babble node', this.nodeID]);

        try {
            // Initialize knowledge of other nodes
            for (let i = 1; i <= this.nodeNum; i++) {
                const peerID = i.toString();
                if (peerID !== this.nodeID) {
                    this.knownEvents[peerID] = null;
                    this.lastSyncTime[peerID] = 0;
                }
            }

            // Create initial event (genesis)
            this.createAndStoreEvent(null, []);
            this.eventCount.created++;

            // Start sync loop
            this.registerTimeEvent({
                name: 'sync',
                params: {}
            }, this.syncInterval);

            // Start heartbeat
            this.registerTimeEvent({
                name: 'heartbeat',
                params: {}
            }, this.heartbeatTimeout * 1000);

            // Start health check for debugging
            this.registerTimeEvent({
                name: 'healthCheck',
                params: {}
            }, 5000);

            this.logger.info(['Node initialized successfully', this.nodeID]);
        } catch (error) {
            this.logger.error(['Failed to initialize node', error.message]);
            throw error;
        }
    }

    /*--------------------------------------
     * Hashgraph Event Management
     *--------------------------------------*/

    // Create and store a new event
    createAndStoreEvent(otherParent, transactions) {
        // Rate limit event creation
        const now = this.clock;
        if (now - this.lastEventCreationTime < 100 && transactions.length === 0) {
            // Skip creating empty events too frequently (except genesis)
            if (this.head !== null) {
                return null;
            }
        }

        this.lastEventCreationTime = now;

        // Create the event
        const event = this.createEvent(this.head, otherParent, transactions);
        if (!event) return null;

        // Store and process the event
        if (this.storeEvent(event)) {
            return event;
        }
        return null;
    }

    // Create a new event
    createEvent(selfParent, otherParent, transactions) {
        const event = {
            creatorID: this.nodeID,
            selfParent: selfParent,
            otherParent: otherParent,
            timestamp: this.clock,
            transactions: transactions || [],
            signature: null,
            round: -1,
            consensus: false,
            isWitness: false,
            hash: null
        };

        // Calculate hash
        event.hash = this._calculateEventHash(event);

        // Sign the event
        event.signature = this._signEvent(event);

        return event;
    }

    // Store and process an event
    storeEvent(event) {
        // Verify event first
        if (!this._verifyEvent(event)) {
            this.logger.warning(['Rejected invalid event', event.hash, 'from', event.creatorID]);
            return false;
        }

        // Check if already stored
        if (this.events[event.hash]) {
            return false; // Already have this event
        }

        // Store the event
        this.events[event.hash] = event;

        // Update head pointer if this is our event
        if (event.creatorID === this.nodeID) {
            this.head = event.hash;
            this.knownEvents[this.nodeID] = event.hash;
        }

        // Update known events for creator
        if (!this.knownEvents[event.creatorID] ||
            (this.events[this.knownEvents[event.creatorID]] &&
                this.events[this.knownEvents[event.creatorID]].timestamp < event.timestamp)) {
            this.knownEvents[event.creatorID] = event.hash;
        }

        // Process the new event
        this.processNewEvent(event);

        // Broadcast the event if it's ours
        if (event.creatorID === this.nodeID) {
            this.broadcastEvent(event);
        }

        return true;
    }

    // Process a new event
    processNewEvent(event) {
        // Add to pending list if not already processed
        if (!this.pendingEvents.includes(event.hash)) {
            this.pendingEvents.push(event.hash);
            this.eventCount.processed++;
        }

        // Run consensus algorithm
        this.runConsensus();
    }

    // Broadcast an event to peers
    broadcastEvent(event) {
        const eventMsg = {
            type: MSG_TYPES.EVENT,
            event: event
        };

        this.send(this.nodeID, 'broadcast', eventMsg);
        this.msgCount.sent++;
    }

    /*--------------------------------------
     * Hashgraph Consensus Algorithm
     *--------------------------------------*/

    // Run the Hashgraph consensus algorithm
    runConsensus() {
        if (this.isSuspended) {
            return;
        }

        try {
            // 1. Divide rounds (assign round numbers to events)
            this.divideRounds();

            // 2. Find consensus order (simplified virtual voting)
            const newConsensusEvents = this.findConsensusOrder();

            // 3. Process newly consensus events
            if (newConsensusEvents.length > 0) {
                this.processConsensusEvents(newConsensusEvents);
            }

            // Check if we should suspend
            this.checkSuspendCondition();
        } catch (error) {
            this.logger.error(['Error in consensus algorithm', error.message]);
        }
    }

    // Divide events into rounds
    divideRounds() {
        // Process all pending events
        const processedEvents = [];

        for (const eventHash of this.pendingEvents) {
            if (!this.events[eventHash]) {
                // Event might have been removed
                processedEvents.push(eventHash);
                continue;
            }

            const event = this.events[eventHash];

            if (event.round < 0) {
                // Find highest round of parents
                let parentRound = -1;

                if (event.selfParent && this.events[event.selfParent]) {
                    parentRound = Math.max(parentRound, this.events[event.selfParent].round);
                }

                if (event.otherParent && this.events[event.otherParent]) {
                    parentRound = Math.max(parentRound, this.events[event.otherParent].round);
                }

                // This event's round is parent's highest round + 1
                event.round = parentRound + 1;

                // Update highest round
                this.round = Math.max(this.round, event.round);

                // Check if witness (first event by creator in this round)
                event.isWitness = this.isWitness(event);

                // Add to witness list if witness
                if (event.isWitness) {
                    if (!this.witnesses[event.round]) {
                        this.witnesses[event.round] = [];
                    }
                    this.witnesses[event.round].push(eventHash);
                }

                processedEvents.push(eventHash);
            }
        }

        // Remove processed events from pending list
        this.pendingEvents = this.pendingEvents.filter(hash => !processedEvents.includes(hash));
    }

    // Check if event is a witness (first event by creator in this round)
    isWitness(event) {
        if (event.round <= 0) {
            return true;  // All events in round 0 are witnesses
        }

        // Check if first event by creator in this round
        if (event.selfParent) {
            const parentEvent = this.events[event.selfParent];
            return parentEvent.round < event.round;
        }

        return true;  // No self-parent, so first event by definition
    }

    // Find events that have reached consensus
    findConsensusOrder() {
        const newConsensus = [];

        // Process all events
        for (const eventHash in this.events) {
            const event = this.events[eventHash];

            // Skip if already consensus
            if (this.consensusEvents.has(eventHash)) {
                continue;
            }

            // Simplified consensus rule: events 2 rounds back are considered consensus
            if (event.round <= this.round - 2) {
                event.consensus = true;
                this.consensusEvents.add(eventHash);
                newConsensus.push(eventHash);
            } else {
                this.undeterminedEvents++;
            }
        }

        return newConsensus;
    }

    // Process events that have reached consensus
    processConsensusEvents(consensusEvents) {
        if (consensusEvents.length === 0) return;

        // Group events by round
        const eventsByRound = {};

        for (const eventHash of consensusEvents) {
            const event = this.events[eventHash];
            if (!eventsByRound[event.round]) {
                eventsByRound[event.round] = [];
            }
            eventsByRound[event.round].push(event);
        }

        // Create block for each round
        for (const round in eventsByRound) {
            const events = eventsByRound[round];
            const transactions = this.collectTransactions(events);

            // Skip empty blocks (except genesis block)
            if (transactions.length === 0 && parseInt(round) > 0) {
                continue;
            }

            const block = {
                index: this.blocks.length,
                round: parseInt(round),
                events: events.map(e => e.hash),
                transactions: transactions,
                timestamp: this.clock,
                signature: null,
                hash: null
            };

            // Calculate block hash
            block.hash = this._calculateBlockHash(block);

            // Sign block
            block.signature = this._signBlock(block);

            // Add block
            this.blocks.push(block);

            // Initialize signature collection
            this.blockSignatures[block.hash] = [
                { nodeID: this.nodeID, signature: block.signature }
            ];

            // Broadcast block
            this.broadcastBlock(block);

            // Check if decided
            if (this.blocks.length > 3) {
                this.isDecided = true;
            }

            this.logger.info(['Created block', block.index, 'with', transactions.length, 'transactions']);
        }
    }

    // Collect transactions from events
    collectTransactions(events) {
        const transactions = [];
        const seenTxs = new Set();

        for (const event of events) {
            if (event.transactions && event.transactions.length > 0) {
                for (const tx of event.transactions) {
                    const txKey = typeof tx === 'object' ? JSON.stringify(tx) : tx;
                    if (!seenTxs.has(txKey)) {
                        transactions.push(tx);
                        seenTxs.add(txKey);
                    }
                }
            }
        }

        return transactions;
    }

    // Broadcast block
    broadcastBlock(block) {
        const blockMsg = {
            type: MSG_TYPES.BLOCK,
            block: block
        };

        this.send(this.nodeID, 'broadcast', blockMsg);
        this.msgCount.sent++;
    }

    // Check suspend condition
    checkSuspendCondition() {
        const suspendLimit = this.config.babble?.suspendLimit || 100;
        if (this.undeterminedEvents > suspendLimit * this.nodeNum) {
            this.isSuspended = true;
            this.logger.warning(['Node suspended due to too many undetermined events']);
        }
    }

    /*--------------------------------------
     * Network Communication Handlers
     *--------------------------------------*/

    // Handle incoming message
    onMsgEvent(msgEvent) {
        super.onMsgEvent(msgEvent);

        try {
            const msg = msgEvent.packet.content;
            const src = msgEvent.packet.src;

            if (!msg || !msg.type) {
                return;
            }

            this.msgCount.received++;

            // Handle different message types
            switch (msg.type) {
                case MSG_TYPES.EVENT:
                    if (msg.event && !this.receivedEvents.has(msg.event.hash)) {
                        this.receivedEvents.add(msg.event.hash);
                        this.storeEvent(msg.event);
                        this.eventCount.received++;
                    }
                    break;

                case MSG_TYPES.BLOCK:
                    this.handleBlock(msg);
                    break;

                case MSG_TYPES.BLOCK_SIGNATURE:
                    this.handleBlockSignature(msg);
                    break;

                case MSG_TYPES.SYNC_REQUEST:
                    this.handleSyncRequest(msg, src);
                    break;

                case MSG_TYPES.SYNC_RESPONSE:
                    this.handleSyncResponse(msg);
                    this.syncCount.responses++;
                    break;

                default:
                    this.logger.warning(['Unknown message type', msg.type]);
            }

        } catch (error) {
            this.logger.error(['Error handling message', error.message]);
        }
    }

    // Handle time events
    onTimeEvent(timeEvent) {
        super.onTimeEvent(timeEvent);

        try {
            const functionMeta = timeEvent.functionMeta;

            switch (functionMeta.name) {
                case 'sync':
                    // Perform sync
                    this.doSync();
                    // Register next sync
                    this.registerTimeEvent({
                        name: 'sync',
                        params: {}
                    }, this.syncInterval);
                    break;

                case 'heartbeat':
                    // Perform heartbeat
                    this.doHeartbeat();
                    // Register next heartbeat
                    this.registerTimeEvent({
                        name: 'heartbeat',
                        params: {}
                    }, this.heartbeatTimeout * 1000);
                    break;

                case 'healthCheck':
                    // Check node health and print stats
                    this.checkNodeHealth();
                    this.registerTimeEvent({
                        name: 'healthCheck',
                        params: {}
                    }, 5000);
                    break;

                default:
                    // Ignore unknown time events
                    break;
            }

        } catch (error) {
            this.logger.error(['Error handling time event', error.message]);
        }
    }

    // Synchronize with another node
    doSync() {
        if (this.isSuspended) {
            return;
        }

        try {
            // Randomly select a peer to sync with
            const peers = Object.keys(this.knownEvents).filter(id => id !== this.nodeID);

            if (peers.length > 0) {
                // Choose the peer that we haven't synced with for the longest time
                let selectedPeer = null;
                let oldestSyncTime = Infinity;

                for (const peer of peers) {
                    const lastSync = this.lastSyncTime[peer] || 0;
                    if (lastSync < oldestSyncTime) {
                        oldestSyncTime = lastSync;
                        selectedPeer = peer;
                    }
                }

                if (selectedPeer) {
                    this.syncEvents(selectedPeer);
                    this.syncCount.requests++;
                }
            }

            // Create new event if there are pending transactions
            if (this.pendingTransactions.length > 0) {
                const txBatch = this.pendingTransactions.splice(0, Math.min(10, this.pendingTransactions.length));
                const newEvent = this.createAndStoreEvent(null, txBatch);
                if (newEvent) {
                    this.eventCount.created++;
                }
            }

        } catch (error) {
            this.logger.error(['Error in sync', error.message]);
        }
    }

    // Create heartbeat event if needed
    doHeartbeat() {
        if (this.isSuspended) {
            return;
        }

        try {
            // Create empty event if no events created recently
            const now = this.clock;
            const timeSinceLastEvent = now - this.lastEventCreationTime;

            if (timeSinceLastEvent > this.heartbeatTimeout * 1000) {
                const newEvent = this.createAndStoreEvent(null, []);
                if (newEvent) {
                    this.eventCount.created++;
                    this.logger.info(['Created heartbeat event', newEvent.hash]);
                }
            }

            // Run consensus
            this.runConsensus();

        } catch (error) {
            this.logger.error(['Error in heartbeat', error.message]);
        }
    }

    // Send sync request to peer
    syncEvents(peer) {
        try {
            const knownEvents = {};
            for (const nodeID in this.knownEvents) {
                if (this.knownEvents[nodeID]) {
                    knownEvents[nodeID] = this.knownEvents[nodeID];
                }
            }

            const syncRequest = {
                type: MSG_TYPES.SYNC_REQUEST,
                knownEvents: knownEvents
            };

            this.send(this.nodeID, peer, syncRequest);
            this.lastSyncTime[peer] = this.clock;
            this.msgCount.sent++;
        } catch (error) {
            this.logger.error(['Error syncing with peer', peer, error.message]);
        }
    }

    // Handle sync request from peer
    handleSyncRequest(msg, src) {
        try {
            const theirKnownEvents = msg.knownEvents || {};
            const eventsToSend = [];

            // Find events the other node doesn't know
            for (const eventHash in this.events) {
                const event = this.events[eventHash];
                const nodeID = event.creatorID;

                if (!theirKnownEvents[nodeID] ||
                    !this.events[theirKnownEvents[nodeID]] ||
                    this.events[theirKnownEvents[nodeID]].timestamp < event.timestamp) {
                    eventsToSend.push(event);
                }
            }

            // Limit response size to avoid overwhelming the network
            const maxEventsToSend = 20; // Adjust as needed
            const limitedEvents = eventsToSend.slice(0, maxEventsToSend);

            // Send response
            const syncResponse = {
                type: MSG_TYPES.SYNC_RESPONSE,
                events: limitedEvents
            };

            this.send(this.nodeID, src, syncResponse);
            this.msgCount.sent++;
        } catch (error) {
            this.logger.error(['Error handling sync request', error.message]);
        }
    }

    // Process sync response
    handleSyncResponse(msg) {
        try {
            const events = msg.events || [];
            let newEvents = false;

            for (const event of events) {
                if (!this.events[event.hash]) {
                    const stored = this.storeEvent(event);
                    if (stored) {
                        newEvents = true;
                    }
                }
            }

            if (newEvents) {
                // Run consensus if new events received
                this.runConsensus();
            }
        } catch (error) {
            this.logger.error(['Error handling sync response', error.message]);
        }
    }

    // Handle received block
    handleBlock(msg) {
        try {
            const block = msg.block;

            // Skip if already processed
            if (this.processedBlocks.has(block.hash)) {
                return;
            }

            this.processedBlocks.add(block.hash);

            // Verify block
            if (!this._verifyBlock(block)) {
                this.logger.warning(['Rejected invalid block', block.hash]);
                return;
            }

            // If new block, save and sign
            if (!this.blocks.some(b => b.hash === block.hash)) {
                this.blocks.push(block);

                // Sign block
                const signature = this._signBlock(block);

                // Send signature
                const signatureMsg = {
                    type: MSG_TYPES.BLOCK_SIGNATURE,
                    blockHash: block.hash,
                    signature: signature,
                    nodeID: this.nodeID
                };

                this.send(this.nodeID, 'broadcast', signatureMsg);
                this.msgCount.sent++;

                // Check if decided
                if (this.blocks.length > 3) {
                    this.isDecided = true;
                }

                this.logger.info(['Received block', block.index, 'with', block.transactions.length, 'transactions']);
            }
        } catch (error) {
            this.logger.error(['Error handling block', error.message]);
        }
    }

    // Handle block signature
    handleBlockSignature(msg) {
        try {
            const { blockHash, signature, nodeID } = msg;

            // Initialize signature collection
            if (!this.blockSignatures[blockHash]) {
                this.blockSignatures[blockHash] = [];
            }

            // Skip if already have this signature
            if (this.blockSignatures[blockHash].some(s => s.nodeID === nodeID)) {
                return;
            }

            // Add signature
            this.blockSignatures[blockHash].push({ nodeID, signature });

            // Check if enough signatures
            if (this.blockSignatures[blockHash].length >= 2 * this.f + 1) {
                // Block has enough signatures, finalize
                const block = this.blocks.find(b => b.hash === blockHash);
                if (block) {
                    block.final = true;
                    this.logger.info(['Block finalized', block.index]);
                }
            }
        } catch (error) {
            this.logger.error(['Error handling block signature', error.message]);
        }
    }

    // Check node health
    checkNodeHealth() {
        const eventCount = Object.keys(this.events).length;
        const blockCount = this.blocks.length;
        const consensusCount = this.consensusEvents.size;
        const pendingCount = this.pendingEvents.length;

        this.logger.info([
            'Node health',
            `NodeID: ${this.nodeID}`,
            `Round: ${this.round}`,
            `Events: ${eventCount} (created: ${this.eventCount.created}, received: ${this.eventCount.received})`,
            `Blocks: ${blockCount}`,
            `Consensus events: ${consensusCount}`,
            `Pending events: ${pendingCount}`,
            `Messages: sent=${this.msgCount.sent}, received=${this.msgCount.received}`,
            `Sync: requests=${this.syncCount.requests}, responses=${this.syncCount.responses}`,
            `Status: suspended=${this.isSuspended}, decided=${this.isDecided}`
        ]);
    }

    /*--------------------------------------
     * Helper Methods
     *--------------------------------------*/

    // Calculate hash of an event
    _calculateEventHash(event) {
        // Create a copy without hash and signature fields
        const eventForHash = {
            creatorID: event.creatorID,
            selfParent: event.selfParent,
            otherParent: event.otherParent,
            timestamp: event.timestamp,
            transactions: event.transactions,
            round: event.round
        };

        return calculateHash(eventForHash);
    }

    // Sign an event
    _signEvent(event) {
        return `signature_${this.nodeID}_${event.hash}`;
    }

    // Verify event signature
    _verifyEventSignature(event) {
        return event.signature &&
            event.signature.startsWith(`signature_${event.creatorID}_${event.hash}`);
    }

    // Calculate hash of a block
    _calculateBlockHash(block) {
        // Create a copy without hash and signature fields
        const blockForHash = {
            index: block.index,
            round: block.round,
            events: block.events,
            transactions: block.transactions,
            timestamp: block.timestamp
        };

        return calculateHash(blockForHash);
    }

    // Sign a block
    _signBlock(block) {
        return `block_signature_${this.nodeID}_${block.hash}`;
    }

    // Verify block
    _verifyBlock(block) {
        // Basic fields check
        if (!block || !block.hash || !block.events || !block.transactions) {
            return false;
        }

        // Check block hash
        const calculatedHash = this._calculateBlockHash(block);
        if (calculatedHash !== block.hash) {
            return false;
        }

        // Verify signature
        return block.signature && block.signature.startsWith(`block_signature_`);
    }

    // Verify event
    _verifyEvent(event) {
        // Basic field validation
        if (!event || !event.hash || !event.creatorID || !event.signature) {
            this.logger.warning(['Rejected invalid event missing basic fields']);
            return false;
        }

        // Verify event hash
        const calculatedHash = this._calculateEventHash(event);
        if (calculatedHash !== event.hash) {
            this.logger.warning(['Rejected event with invalid hash']);
            return false;
        }

        // Verify event signature
        if (!this._verifyEventSignature(event)) {
            this.logger.warning(['Rejected event with invalid signature']);
            return false;
        }

        // Verify timestamp is reasonable
        if (event.timestamp > this.clock + 10000) { // Allow 10 seconds future time
            this.logger.warning(['Rejected event with future timestamp']);
            return false;
        }

        // Check for known fork
        if (event.selfParent && this._isKnownFork(event)) {
            this.logger.warning(['Detected fork event']);
            return false;
        }

        return true;
    }

    // Detect known forks
    _isKnownFork(event) {
        // Look for other events claiming the same parent
        for (const hash in this.events) {
            const existingEvent = this.events[hash];

            // If found another event from same creator, using same parent but different hash
            if (existingEvent.creatorID === event.creatorID &&
                existingEvent.selfParent === event.selfParent &&
                existingEvent.hash !== event.hash) {
                return true;
            }
        }

        return false;
    }
}

/**
 * Byzantine node implementations that intentionally deviate from the protocol
 */

// Base Byzantine node class
class ByzantineLibP2PBabbleNode extends LibP2PBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.isByzantine = true;
        this.byzantineType = "generic";

        this.logger.warning(['Created Byzantine node', this.byzantineType, nodeID]);
    }

    // Override message handling with Byzantine behavior
    onMsgEvent(msgEvent) {
        // Randomly drop messages
        if (Math.random() < 0.3) {
            return;
        }

        super.onMsgEvent(msgEvent);
    }

    // Create potentially malicious events
    createEvent(selfParent, otherParent, transactions) {
        // Choose Byzantine behavior based on random chance
        const byzantineChoice = Math.random();

        if (byzantineChoice < 0.3) {
            // Create invalid event with non-existent parent
            return super.createEvent("invalid_parent", otherParent, transactions);
        } else if (byzantineChoice < 0.6) {
            // Don't reference other nodes (hinders consensus)
            return super.createEvent(selfParent, null, transactions);
        }

        // Normal behavior
        return super.createEvent(selfParent, otherParent, transactions);
    }
}

// Delaying node - intentionally introduces delays
class DelayingNode extends ByzantineLibP2PBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.byzantineType = "delaying";
        this.delayedMessages = [];

        this.logger.warning(['Created Delaying Byzantine node', nodeID]);
    }

    // Delay message processing
    onMsgEvent(msgEvent) {
        // Randomly delay messages
        if (Math.random() < 0.6) {
            const delay = 2 + Math.random() * 3;  // 2-5 second delay
            this.registerTimeEvent(
                { name: 'delayedMsg', params: { msg: msgEvent } },
                delay * 1000
            );
            return;
        }

        // Process normally
        super.onMsgEvent(msgEvent);
    }

    // Handle delayed messages
    onTimeEvent(timeEvent) {
        const functionMeta = timeEvent.functionMeta;

        if (functionMeta.name === 'delayedMsg') {
            super.onMsgEvent(functionMeta.params.msg);
        } else {
            super.onTimeEvent(timeEvent);
        }
    }
}

// Forking node - creates event forks
class ForkingNode extends ByzantineLibP2PBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.byzantineType = "forking";
        this.forkEvents = {};

        this.logger.warning(['Created Forking Byzantine node', nodeID]);
    }

    // Create forked events
    createAndStoreEvent(otherParent, transactions) {
        // Create main event
        const event1 = super.createEvent(this.head, otherParent, transactions);
        if (!event1) return null;

        this.storeEvent(event1);

        // Store forked events for different nodes
        this.forkEvents[event1.hash] = {};

        for (let i = 1; i <= this.nodeNum; i++) {
            const peerID = i.toString();
            if (peerID !== this.nodeID) {
                // Create a fork with same parent but different transactions
                const forkTxs = ["FORK_" + peerID + "_" + Math.floor(Math.random() * 1000)];
                const forkEvent = super.createEvent(this.head, otherParent, forkTxs);
                if (forkEvent) {
                    this.forkEvents[event1.hash][peerID] = forkEvent;
                }
            }
        }

        return event1;
    }

    // Send different events to different peers
    broadcastEvent(event) {
        // If we have forks for this event
        if (this.forkEvents[event.hash]) {
            for (const peerID in this.forkEvents[event.hash]) {
                const forkEvent = this.forkEvents[event.hash][peerID];
                const eventMsg = {
                    type: MSG_TYPES.EVENT,
                    event: forkEvent
                };

                this.send(this.nodeID, peerID, eventMsg);
                this.msgCount.sent++;
            }
        } else {
            // No forks, just broadcast normally
            const eventMsg = {
                type: MSG_TYPES.EVENT,
                event: event
            };

            this.send(this.nodeID, 'broadcast', eventMsg);
            this.msgCount.sent++;
        }
    }
}

// Equivocating node - provides inconsistent responses
class EquivocatingNode extends ByzantineLibP2PBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.byzantineType = "equivocating";
        this.syncResponses = {};

        this.logger.warning(['Created Equivocating Byzantine node', nodeID]);
    }

    // Provide different sync responses to different nodes
    handleSyncRequest(msg, src) {
        // Randomly decide whether to equivocate
        if (Math.random() < 0.5) {
            // Create node-specific response
            const eventsToSend = [];

            // Selectively include events
            for (const eventHash in this.events) {
                if (Math.random() < 0.7) {  // 70% chance to include each event
                    eventsToSend.push(this.events[eventHash]);
                }
            }

            // Save this response for later comparison
            this.syncResponses[src] = eventsToSend.map(e => e.hash);

            // Send the partial response
            const syncResponse = {
                type: MSG_TYPES.SYNC_RESPONSE,
                events: eventsToSend
            };

            this.send(this.nodeID, src, syncResponse);
            this.msgCount.sent++;
        } else {
            // Normal response
            super.handleSyncRequest(msg, src);
        }
    }
}

// Factory function to create Byzantine nodes of the right type
function createByzantineNode(type, nodeID, nodeNum, network, registerTimeEvent, customConfig) {
    switch (type) {
        case 'forking':
            return new ForkingNode(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        case 'equivocating':
            return new EquivocatingNode(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        case 'delaying':
            return new DelayingNode(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        default:
            return new ByzantineLibP2PBabbleNode(nodeID, nodeNum, network, registerTimeEvent, customConfig);
    }
}

// Export the main node class
module.exports = LibP2PBabbleNode;
// Export Byzantine node factory
module.exports.createByzantineNode = createByzantineNode;