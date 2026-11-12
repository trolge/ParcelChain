// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * ChainParcel - A Blockchain Delivery Tracking and Escrow Contract
 *
 * ACADEMIC NOTE:
 * This contract intentionally contains vulnerabilities from the
 * OWASP Smart Contract Top 10 (2025) for a class assignment. It is
 * built for testing on the Sepolia testnet only, never mainnet.
 *
 * Intentional vulnerabilities:
 *   1. SC01 - Access Control Vulnerability   -> assignCourier(), updateStatus()
 *   2. SC05 - Reentrancy                     -> claimRefund()
 *
 * See the comments marked "VULNERABILITY" below for details.
 */
contract ChainParcel {

    enum Status { Created, Assigned, PickedUp, InTransit, Delivered, Confirmed, Refunded, Cancelled }

    struct Shipment {
        address sender;
        address receiver;
        address courier;
        uint256 fee;
        uint256 deadline;      // unix timestamp
        Status status;
        bool paidOut;          // tracks whether courier has already been paid
        bool refunded;         // tracks whether sender has already been refunded
    }

    address public owner;
    uint256 public shipmentCount;
    mapping(uint256 => Shipment) public shipments;
    mapping(address => bool) public registeredCouriers;

    event ShipmentCreated(uint256 indexed id, address indexed sender, address indexed receiver, uint256 fee, uint256 deadline);
    event CourierAssigned(uint256 indexed id, address indexed courier);
    event StatusUpdated(uint256 indexed id, Status newStatus);
    event DeliveryConfirmed(uint256 indexed id);
    event PaymentReleased(uint256 indexed id, address indexed courier, uint256 amount);
    event RefundClaimed(uint256 indexed id, address indexed sender, uint256 amount);
    event ShipmentCancelled(uint256 indexed id);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier shipmentExists(uint256 id) {
        require(id < shipmentCount, "Shipment does not exist");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ---------------------------------------------------------------
    // Courier registry (kept simple/real; not part of the vuln plan)
    // ---------------------------------------------------------------

    function registerCourier(address courier) external onlyOwner {
        registeredCouriers[courier] = true;
    }

    // ---------------------------------------------------------------
    // Sender actions
    // ---------------------------------------------------------------

    function createShipment(address receiver, uint256 deadline) external payable returns (uint256) {
        require(msg.value > 0, "Fee required");
        require(receiver != address(0), "Invalid receiver");
        require(deadline > block.timestamp, "Deadline must be in the future");

        uint256 id = shipmentCount++;
        shipments[id] = Shipment({
            sender: msg.sender,
            receiver: receiver,
            courier: address(0),
            fee: msg.value,
            deadline: deadline,
            status: Status.Created,
            paidOut: false,
            refunded: false
        });

        emit ShipmentCreated(id, msg.sender, receiver, msg.value, deadline);
        return id;
    }

    function cancelShipment(uint256 id) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(msg.sender == s.sender, "Not sender");
        require(s.status == Status.Created, "Already picked up");

        s.status = Status.Cancelled;
        emit ShipmentCancelled(id);
    }

    /**
     * VULNERABILITY 2: Reentrancy (OWASP SC05)
     * ------------------------------------------------------------
     * The external call (sending ETH back to msg.sender) happens
     * BEFORE the state is updated (s.refunded = true / fee = 0).
     * A malicious contract calling this function can re-enter
     * claimRefund() from its receive()/fallback() function and
     * drain the escrowed fee multiple times, taking funds that
     * belong to other shipments' senders and couriers.
     *
     * Fix (do NOT apply yet - this is intentional for the assignment):
     *   Follow checks-effects-interactions: set s.refunded = true
     *   and zero out s.fee BEFORE making the external call, or use
     *   a reentrancy guard (nonReentrant modifier).
     */
    function claimRefund(uint256 id) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(msg.sender == s.sender, "Not sender");
        require(!s.refunded, "Already refunded");
        require(
            s.status == Status.Cancelled ||
            (block.timestamp > s.deadline && s.status != Status.Confirmed),
            "Not eligible for refund"
        );

        uint256 amount = s.fee;

        // --- VULNERABLE LINE: external call before state update ---
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Refund transfer failed");

        s.refunded = true;     // state updated AFTER the external call
        s.status = Status.Refunded;

        emit RefundClaimed(id, msg.sender, amount);
    }

    // ---------------------------------------------------------------
    // Logistics company actions
    // ---------------------------------------------------------------

    /**
     * VULNERABILITY 1: Access Control Vulnerability (OWASP SC01)
     * ------------------------------------------------------------
     * This function is meant to be restricted to the logistics
     * company (owner), but the onlyOwner modifier is intentionally
     * left off. Any address can assign itself (or anyone else) as
     * the courier for any shipment.
     *
     * Combined with updateStatus() below (which also lacks a
     * "msg.sender == s.courier" check), an attacker can:
     *   1. Call assignCourier(id, attackerAddress)
     *   2. Call updateStatus(id, Status.Delivered)
     *   3. Call releasePayment(id) to steal the escrowed fee
     *      without ever delivering the parcel.
     *
     * Fix (do NOT apply yet - this is intentional for the assignment):
     *   Add `onlyOwner` to assignCourier(), and require
     *   `registeredCouriers[courier] == true`.
     */
    function assignCourier(uint256 id, address courier) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(s.status == Status.Created, "Already assigned");

        s.courier = courier;
        s.status = Status.Assigned;

        emit CourierAssigned(id, courier);
    }

    // ---------------------------------------------------------------
    // Courier actions
    // ---------------------------------------------------------------

    /**
     * Also part of VULNERABILITY 1 (OWASP SC01):
     * This function should check `msg.sender == s.courier`, but
     * that check is intentionally omitted so any address can move
     * any shipment straight to Delivered.
     *
     * Fix (do NOT apply yet):
     *   require(msg.sender == s.courier, "Not assigned courier");
     */
    function updateStatus(uint256 id, Status newStatus) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(
            newStatus == Status.PickedUp ||
            newStatus == Status.InTransit ||
            newStatus == Status.Delivered,
            "Invalid status transition"
        );

        s.status = newStatus;
        emit StatusUpdated(id, newStatus);
    }

    // ---------------------------------------------------------------
    // Receiver action
    // ---------------------------------------------------------------

    function confirmDelivery(uint256 id) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(msg.sender == s.receiver, "Not receiver");
        require(s.status == Status.Delivered, "Not marked delivered yet");

        s.status = Status.Confirmed;
        emit DeliveryConfirmed(id);
    }

    // ---------------------------------------------------------------
    // Payment release
    // ---------------------------------------------------------------

    function releasePayment(uint256 id) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(s.status == Status.Confirmed, "Delivery not confirmed");
        require(!s.paidOut, "Already paid");
        require(msg.sender == s.courier, "Not the assigned courier");

        uint256 amount = s.fee;
        s.paidOut = true; // state updated before transfer (this one follows best practice)

        (bool success, ) = s.courier.call{value: amount}("");
        require(success, "Payment transfer failed");

        emit PaymentReleased(id, s.courier, amount);
    }

    // ---------------------------------------------------------------
    // View helpers
    // ---------------------------------------------------------------

    function getShipment(uint256 id) external view shipmentExists(id) returns (
        address sender,
        address receiver,
        address courier,
        uint256 fee,
        uint256 deadline,
        Status status,
        bool paidOut,
        bool refunded
    ) {
        Shipment storage s = shipments[id];
        return (s.sender, s.receiver, s.courier, s.fee, s.deadline, s.status, s.paidOut, s.refunded);
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
