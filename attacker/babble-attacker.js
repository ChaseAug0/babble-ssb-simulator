'use strict';

/**
 * EnhancedBabbleAttacker - A comprehensive attacker for the Babble consensus protocol
 * 
 * This attacker combines multiple strategies:
 * 1. Event tampering - Modifies events to create forks and inject fake transactions
 * 2. Selective delay - Holds back critical messages to slow consensus
 * 3. Equivocation - Sends different information to different nodes
 * 4. Network partition simulation - Creates dynamic network partitions
 * 5. Round skipping - Manipulates round assignments to create inconsistencies
 */
class BabbleAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // Network partition configuration
        this.partitionActive = false;
        this.partitionDuration = 5; // 5 seconds

        // Delayed message storage
        this.delayedMessages = [];
        this.maxDelay = 10; // Maximum delay in seconds

        // Attack intensity parameters (can be tuned)
        this.tamperingRate = 0.3;     // 30% of events get tampered
        this.equivocationRate = 0.25; // 25% of events get equivocation
        this.messageDelayRate = 0.2;  // 20% of messages get delayed
        this.targetHighRounds = true; // Target higher rounds for greater impact

        // Track events and nodes for sophisticated attacks
        this.seenEvents = new Set();        // Track event hashes we've seen
        this.nodeRoundState = {};           // Track node progress 
        this.lastAttackTime = getClockTime();
        this.attackPhase = 0;               // Rotate attack strategies

        // Initialize attack cycle
        this.cycleAttackStrategies();
    }

    /**
     * Main attack method - processes all packets passing through the network
     */
    attack(packets) {
        const currentTime = this.getClockTime();
        const processedPackets = [];

        // Release any delayed messages that are due to be sent
        this.releaseDelayedMessages(currentTime);

        // Process each packet through our attack pipeline
        for (const packet of packets) {
            // Skip processing Byzantine nodes' messages (optional - remove for indirect interference)
            // if (parseInt(packet.src) > (this.nodeNum - this.byzantineNodeNum)) {
            //     processedPackets.push(packet);
            //     continue;
            // }

            // Apply network partition if active
            if (this.partitionActive && !this.canPassPartition(packet)) {
                continue; // Drop packet
            }

            // Apply different attack strategies based on message type
            if (packet.content) {
                const msgType = packet.content.type;
                let modifiedPacket = packet;

                // Update our knowledge of node states based on message contents
                this.updateNodeState(packet);

                // Apply targeted attacks based on message type
                if (msgType === 'babble-event') {
                    modifiedPacket = this.attackBabbleEvent(packet);
                } else if (msgType === 'babble-block' || msgType === 'babble-block-signature') {
                    modifiedPacket = this.attackConsensusMessages(packet);
                } else if (msgType === 'babble-sync-request' || msgType === 'babble-sync-response') {
                    modifiedPacket = this.attackSyncMessages(packet);
                } else if (msgType === 'ssb-message') {
                    modifiedPacket = this.attackSSBMessages(packet);
                }

                // Randomly delay some messages
                if (Math.random() < this.messageDelayRate) {
                    this.delayMessage(modifiedPacket, Math.random() * this.maxDelay);
                    continue; // Skip adding to processed packets
                }

                processedPackets.push(modifiedPacket);
            } else {
                // Non-content packets pass through
                processedPackets.push(packet);
            }
        }

        return processedPackets;
    }

    /**
     * Check if a packet can pass the current network partition
     */
    canPassPartition(packet) {
        // Split network into two groups based on node ID parity
        const srcGroup = parseInt(packet.src) % 2;
        const dstGroup = parseInt(packet.dst) % 2;

        // Only allow communication within the same group
        return srcGroup === dstGroup;
    }

    /**
     * Attack strategy for Babble event messages - the core of the hashgraph
     */
    attackBabbleEvent(packet) {
        const event = packet.content.event;

        // Track the event
        if (event.hash) {
            this.seenEvents.add(event.hash);
        }

        // Apply tampering attack based on our current rate
        if (Math.random() < this.tamperingRate) {
            // Choose an attack strategy
            const attackStrategy = Math.random();

            if (attackStrategy < 0.25) {
                // Strategy 1: Destroy event chain by nullifying parent reference
                event.selfParent = null;
            } else if (attackStrategy < 0.5) {
                // Strategy 2: Inject malicious transactions
                event.transactions = ["MALICIOUS_TX_" + Math.random().toString(36).substring(2, 9)];
            } else if (attackStrategy < 0.75) {
                // Strategy 3: Corrupt round number for round-based attacks
                // High round numbers will be treated as more important in many protocols
                event.round = event.round ? event.round + Math.floor(Math.random() * 3) : 1;
            } else {
                // Strategy 4: Change creator ID - causes confusion in the protocol
                if (event.creatorID && event.creatorID !== packet.src) {
                    // Make it look like another node created this event
                    const fakeCreator = (parseInt(event.creatorID) % this.nodeNum) + 1;
                    event.creatorID = fakeCreator.toString();
                }
            }
        }

        // Apply equivocation attack (sending different versions to different nodes)
        if (Math.random() < this.equivocationRate && packet.dst !== 'broadcast') {
            // Create a slightly different event hash
            if (event.hash) {
                event.hash = event.hash.replace(/.$/, Math.floor(Math.random() * 10));
            }

            // If we're targeting a specific node, we might corrupt event data
            // in a way that might only be detected later during consensus
            const dstNodeId = parseInt(packet.dst);
            if (dstNodeId <= this.nodeNum - this.byzantineNodeNum) {
                // Create a subtle corruption that will only affect later consensus
                if (event.timestamp) {
                    // Adjust timestamp slightly - can affect event ordering
                    event.timestamp += Math.floor(Math.random() * 1000) - 500;
                }
            }
        }

        return packet;
    }

    /**
     * Attack strategy for consensus messages (blocks and signatures)
     */
    attackConsensusMessages(packet) {
        // Consensus messages are critical - tampering with them can heavily disrupt the protocol

        if (packet.content.type === 'babble-block') {
            const block = packet.content.block;

            // Only attack blocks from higher rounds for maximum impact
            if (this.targetHighRounds && block.round && block.round > 1) {
                if (Math.random() < 0.4) {
                    // Corrupt the block events - this will cause consensus failures
                    if (block.events && block.events.length > 0) {
                        const randomIndex = Math.floor(Math.random() * block.events.length);
                        // Modify an event hash in the block
                        block.events[randomIndex] = 'fake_' + Math.random().toString(36).substring(2, 15);
                    }

                    // Recalculate block hash to make it seem valid
                    if (block.hash) {
                        block.hash = 'hash_' + Math.random().toString(36).substring(2, 15);
                    }
                }
            }
        } else if (packet.content.type === 'babble-block-signature') {
            // Occasionally corrupt signatures to make blocks unverifiable
            if (Math.random() < 0.3) {
                packet.content.signature = 'corrupted_signature_' + Math.random().toString(36).substring(2);
            }
        }

        return packet;
    }

    /**
     * Attack strategy for sync messages (which help nodes catch up)
     */
    attackSyncMessages(packet) {
        if (packet.content.type === 'babble-sync-request') {
            // No major tampering with sync requests - let them go through
            // This ensures nodes will try to sync, setting them up for corrupt sync responses
        } else if (packet.content.type === 'babble-sync-response') {
            // Corrupt sync responses to create inconsistent views
            if (Math.random() < 0.35) {
                // Randomly drop some events from sync responses
                if (packet.content.events && packet.content.events.length > 2) {
                    const dropCount = Math.floor(packet.content.events.length * 0.3);
                    for (let i = 0; i < dropCount; i++) {
                        const randomIndex = Math.floor(Math.random() * packet.content.events.length);
                        packet.content.events.splice(randomIndex, 1);
                    }
                }
            }
        }

        return packet;
    }

    /**
     * Attack strategy for SSB messages
     */
    attackSSBMessages(packet) {
        const message = packet.content.message;

        if (message && Math.random() < 0.25) {
            // Corrupt the sequence number to break the SSB chain
            if (message.sequence) {
                message.sequence += Math.floor(Math.random() * 3) - 1;
                if (message.sequence < 1) message.sequence = 1;
            }

            // Change message content subtly
            if (message.content) {
                // If it's an object, modify or add a random property
                if (typeof message.content === 'object') {
                    message.content.corrupted = true;
                }
            }
        }

        return packet;
    }

    /**
     * Store a message to be released after a delay
     */
    delayMessage(packet, delaySeconds) {
        const releaseTime = this.getClockTime() + delaySeconds;
        this.delayedMessages.push({
            packet: packet,
            releaseTime: releaseTime
        });
    }

    /**
     * Release delayed messages that are due
     */
    releaseDelayedMessages(currentTime) {
        const messagesToRelease = this.delayedMessages.filter(
            item => item.releaseTime <= currentTime
        );

        this.delayedMessages = this.delayedMessages.filter(
            item => item.releaseTime > currentTime
        );

        // Re-introduce delayed messages
        for (const item of messagesToRelease) {
            this.transfer([item.packet]);
        }
    }

    /**
     * Update our knowledge of node states based on message contents
     */
    updateNodeState(packet) {
        const nodeId = packet.src;
        if (!this.nodeRoundState[nodeId]) {
            this.nodeRoundState[nodeId] = { round: 0, events: 0 };
        }

        if (packet.content && packet.content.type === 'babble-event') {
            const event = packet.content.event;
            if (event.round) {
                this.nodeRoundState[nodeId].round = Math.max(
                    this.nodeRoundState[nodeId].round,
                    event.round
                );
            }
            this.nodeRoundState[nodeId].events++;
        }
    }

    /**
     * Toggle network partition attack
     */
    togglePartition() {
        this.partitionActive = !this.partitionActive;
        console.log(`Network partition ${this.partitionActive ? 'activated' : 'deactivated'}`);

        // Schedule next partition toggle
        this.registerAttackerTimeEvent(
            { name: 'togglePartition' },
            this.partitionDuration * 1000
        );
    }

    /**
     * Cycle through different attack strategies
     */
    cycleAttackStrategies() {
        // Change attack parameters periodically to make it more unpredictable
        this.attackPhase = (this.attackPhase + 1) % 4;

        switch (this.attackPhase) {
            case 0: // Heavy event tampering phase
                this.tamperingRate = 0.4;
                this.equivocationRate = 0.2;
                this.messageDelayRate = 0.1;
                this.partitionActive = false;
                break;

            case 1: // Network partition phase
                this.tamperingRate = 0.15;
                this.equivocationRate = 0.15;
                this.messageDelayRate = 0.1;
                this.partitionActive = true;
                break;

            case 2: // Message delay phase
                this.tamperingRate = 0.2;
                this.equivocationRate = 0.1;
                this.messageDelayRate = 0.4;
                this.partitionActive = false;
                break;

            case 3: // Equivocation phase
                this.tamperingRate = 0.2;
                this.equivocationRate = 0.5;
                this.messageDelayRate = 0.15;
                this.partitionActive = false;
                break;
        }

        // Schedule next strategy change
        this.registerAttackerTimeEvent(
            { name: 'cycleAttackStrategies' },
            15 * 1000 // Change strategy every 15 seconds
        );
    }

    /**
     * Handle time-based events
     */
    onTimeEvent(event) {
        const functionMeta = event.functionMeta;

        if (functionMeta.name === 'togglePartition') {
            this.togglePartition();
        } else if (functionMeta.name === 'cycleAttackStrategies') {
            this.cycleAttackStrategies();
        }
    }

    /**
     * Required by simulator framework
     */
    updateParam() {
        return false; // Return false to indicate no parameter updates
    }
}

module.exports = BabbleAttacker;