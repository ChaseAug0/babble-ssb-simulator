'use strict';

const Node = require('../node');
const uuid = require('uuid/v4');

// Message types
const MSG_TYPES = {
    EVENT: 'babble-event',
    SYNC_REQUEST: 'babble-sync-request',
    SYNC_RESPONSE: 'babble-sync-response',
    BLOCK: 'babble-block',
    BLOCK_SIGNATURE: 'babble-block-signature',
    SSB_MESSAGE: 'ssb-message',
    SSB_SYNC_REQUEST: 'ssb-sync-request',
    SSB_SYNC_RESPONSE: 'ssb-sync-response'
};

// Helper function to calculate hash
function calculateHash(data) {
    return 'hash_' + Math.random().toString(36).substring(2, 15);
}

// Main LibP2P-Babble node implementation
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

        // SSB-related structures
        this.ssbMessages = {};
        this.ssbFeed = {};

        // Babble hash graph structures
        this.events = {};
        this.head = null;
        this.witnesses = {};
        this.pendingEvents = [];
        this.knownEvents = {};

        // Consensus and block related
        this.round = 0;
        this.blocks = [];
        this.pendingTransactions = [];
        this.consensusEvents = new Set();
        this.blockSignatures = {};

        // Time and sync
        this.syncInterval = this.config.babble?.syncInterval || 1000;
        this.lastSyncTime = {};
        this.heartbeatTimeout = this.config.lambda || 3;
        this.isDecided = false;
        this.isSuspended = false;
        this.undeterminedEvents = 0;

        // Initialize the node
        this.initialize();
    }

    // Initialize the node
    initialize() {
        // Initialize connections to other nodes
        for (let i = 1; i <= this.nodeNum; i++) {
            const peerID = i.toString();
            if (peerID !== this.nodeID) {
                this.knownEvents[peerID] = null;
                this.lastSyncTime[peerID] = 0;
            }
        }

        // Create initial event
        this.createAndStoreEvent();

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
    }

    // Create and store a new event
    createAndStoreEvent(otherParent, transactions) {
        const event = this.createEvent(this.head, otherParent, transactions);
        this.storeEvent(event);
        return event;
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

    // Store an event
    storeEvent(event) {
        // Store the event
        this.events[event.hash] = event;

        // Update head pointer
        if (event.creatorID === this.nodeID) {
            this.head = event.hash;
            this.knownEvents[this.nodeID] = event.hash;
        }

        // Update known events
        if (!this.knownEvents[event.creatorID] ||
            this.events[this.knownEvents[event.creatorID]].timestamp < event.timestamp) {
            this.knownEvents[event.creatorID] = event.hash;
        }

        // Process the new event
        this.processNewEvent(event);
    }

    // Process a new event
    processNewEvent(event) {
        // Add to pending list
        this.pendingEvents.push(event.hash);

        // Run consensus algorithm
        this.runConsensus();
    }

    // Run consensus algorithm
    runConsensus() {
        if (this.isSuspended) {
            return;
        }

        // 1. Assign rounds to events
        this.divideRounds();

        // 2. Decide fame of witnesses (simplified)
        // In a real implementation, we would use virtual voting here

        // 3. Find consensus order
        const newConsensusEvents = this.findConsensusOrder();

        // 4. Process newly consensus events
        if (newConsensusEvents.length > 0) {
            this.processConsensusEvents(newConsensusEvents);
        }

        // Check if we should suspend
        this.checkSuspendCondition();
    }

    // Divide rounds
    divideRounds() {
        // Process all pending events
        for (const eventHash of this.pendingEvents) {
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

                // Check if witness
                event.isWitness = this.isWitness(event);

                // Add to witness list if witness
                if (event.isWitness) {
                    if (!this.witnesses[event.round]) {
                        this.witnesses[event.round] = [];
                    }
                    this.witnesses[event.round].push(eventHash);
                }
            }
        }

        // Clear pending list
        this.pendingEvents = [];
    }

    // Check if event is a witness
    isWitness(event) {
        if (event.round <= 0) {
            return true;  // All events in round 0 are witnesses
        }

        // Check if first event by creator in this round
        if (event.selfParent) {
            const parentEvent = this.events[event.selfParent];
            return parentEvent.round < event.round;
        }

        return true;  // No self-parent, so first event
    }

    // Find consensus order
    findConsensusOrder() {
        const newConsensus = [];

        // Process all events
        for (const eventHash in this.events) {
            const event = this.events[eventHash];

            // Skip if already consensus
            if (this.consensusEvents.has(eventHash)) {
                continue;
            }

            // Simplified: Events 2 rounds back are considered consensus
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

    // Process consensus events
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
        }
    }

    // Collect transactions from events
    collectTransactions(events) {
        const transactions = [];
        const seenTxs = new Set();

        for (const event of events) {
            for (const tx of event.transactions) {
                if (!seenTxs.has(tx)) {
                    transactions.push(tx);
                    seenTxs.add(tx);
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
    }

    // Check suspend condition
    checkSuspendCondition() {
        const suspendLimit = this.config.babble?.suspendLimit || 100;
        if (this.undeterminedEvents > suspendLimit * this.nodeNum) {
            this.isSuspended = true;
            this.logger.warning(['Node suspended due to too many undetermined events']);
        }
    }

    // Handle message event
    onMsgEvent(msgEvent) {
        super.onMsgEvent(msgEvent);
        const msg = msgEvent.packet.content;
        const src = msgEvent.packet.src;

        // Handle different message types
        switch (msg.type) {
            case MSG_TYPES.EVENT:
                this.storeEvent(msg.event);
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
                break;

            default:
                // Handle other message types as needed
                break;
        }
    }

    // Handle time event
    onTimeEvent(timeEvent) {
        super.onTimeEvent(timeEvent);
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

            default:
                // Handle other time events
                break;
        }
    }

    // Perform sync
    doSync() {
        if (this.isSuspended) {
            return;
        }

        // Randomly select a peer to sync with
        const peers = Object.keys(this.knownEvents).filter(id => id !== this.nodeID);

        if (peers.length > 0) {
            const peer = peers[Math.floor(Math.random() * peers.length)];
            this.syncEvents(peer);
        }

        // Create new event if there are pending transactions
        if (this.pendingTransactions.length > 0) {
            const txs = this.pendingTransactions.splice(0, 10);
            this.createAndStoreEvent(null, txs);
        }
    }

    // Perform heartbeat
    doHeartbeat() {
        if (this.isSuspended) {
            return;
        }

        // Create empty event if no pending transactions
        if (this.pendingTransactions.length === 0) {
            this.createAndStoreEvent();
        }

        // Run consensus
        this.runConsensus();
    }

    // Sync events with peer
    syncEvents(peer) {
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
    }

    // Handle sync request
    handleSyncRequest(msg, src) {
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

        // Send response
        const syncResponse = {
            type: MSG_TYPES.SYNC_RESPONSE,
            events: eventsToSend
        };

        this.send(this.nodeID, src, syncResponse);
    }

    // Handle sync response
    handleSyncResponse(msg) {
        const events = msg.events || [];
        let newEvents = false;

        for (const event of events) {
            if (!this.events[event.hash]) {
                this.storeEvent(event);
                newEvents = true;
            }
        }

        if (newEvents) {
            // Run consensus if new events
            this.runConsensus();
        }
    }

    // Handle block
    handleBlock(msg) {
        const block = msg.block;

        // Verify block
        if (!this._verifyBlock(block)) {
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

            // Check if decided
            if (this.blocks.length > 3) {
                this.isDecided = true;
            }
        }
    }

    // Handle block signature
    handleBlockSignature(msg) {
        const { blockHash, signature, nodeID } = msg;

        // Initialize signature collection
        if (!this.blockSignatures[blockHash]) {
            this.blockSignatures[blockHash] = [];
        }

        // Add signature
        if (!this.blockSignatures[blockHash].some(s => s.nodeID === nodeID)) {
            this.blockSignatures[blockHash].push({ nodeID, signature });
        }

        // Check if enough signatures
        if (this.blockSignatures[blockHash].length >= 2 * this.f + 1) {
            // Block has enough signatures, finalize
            const block = this.blocks.find(b => b.hash === blockHash);
            if (block) {
                block.final = true;
            }
        }
    }

    // Helper methods
    _calculateEventHash(event) {
        const data = `${event.creatorID}|${event.selfParent}|${event.otherParent}|${event.timestamp}|${JSON.stringify(event.transactions)}`;
        return calculateHash(data);
    }

    _signEvent(event) {
        return `signature_${this.nodeID}_${event.hash}`;
    }

    _calculateBlockHash(block) {
        const data = `${block.index}|${block.round}|${JSON.stringify(block.events)}|${JSON.stringify(block.transactions)}|${block.timestamp}`;
        return calculateHash(data);
    }

    _signBlock(block) {
        return `block_signature_${this.nodeID}_${block.hash}`;
    }

    _verifyBlock(block) {
        // Basic fields check
        if (!block || !block.hash || !block.events || !block.transactions) {
            return false;
        }

        // Verify events
        for (const eventHash of block.events) {
            if (!this.events[eventHash]) {
                return false;
            }
        }

        // Verify signature
        if (block.signature) {
            return block.signature.startsWith(`block_signature_`);
        }

        return true;
    }
}

// Byzantine node base class that implements malicious behavior
class ByzantineLibP2PBabbleNode extends LibP2PBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.isByzantine = true;
        this.byzantineType = "generic";
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
    }

    // Create forked events
    createAndStoreEvent(otherParent, transactions) {
        // Create main event
        const event1 = this.createEvent(this.head, otherParent, transactions);
        this.storeEvent(event1);

        // Store forked events for different nodes
        this.forkEvents[event1.hash] = {};

        for (let i = 1; i <= this.nodeNum; i++) {
            const peerID = i.toString();
            if (peerID !== this.nodeID) {
                // Create a fork with same parent but different transactions
                const forkEvent = this.createEvent(this.head, otherParent, ["FORK_" + peerID]);
                this.forkEvents[event1.hash][peerID] = forkEvent;
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
            }
        } else {
            // No forks, just broadcast normally
            const eventMsg = {
                type: MSG_TYPES.EVENT,
                event: event
            };

            this.send(this.nodeID, 'broadcast', eventMsg);
        }
    }
}

// Equivocating node - provides inconsistent responses
class EquivocatingNode extends ByzantineLibP2PBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.byzantineType = "equivocating";
        this.syncResponses = {};
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