// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ParcelChain {
    enum Status { Created, Assigned, PickedUp, InTransit, Delivered, Confirmed, Refunded, Cancelled }

    struct Shipment {
        address sender;
        address receiver;
        address courier;
        uint256 fee;
        uint256 deadline;
        Status status;
        bool isPaid;
        bool isRefunded;
    }

    address public owner;
    uint256 public shipmentCount;
    mapping(uint256 => Shipment) public shipments;
    mapping(address => uint256[]) private addressToShipments;
    mapping(address => bool) public registeredCouriers;

    event ShipmentCreated(uint256 indexed id, address indexed sender, address indexed receiver, uint256 fee, uint256 deadline);
    event CourierAssigned(uint256 indexed id, address indexed courier);
    event StatusUpddated(uint256 indexed id, Status newStatus);
    event DeliveryConfirmed(uint256 indexed id);
    event PaymentReleased(uint256 indexed id, address indexed courier, uint256 amount);
    event RefundClaimed(uint256 indexed id, address indexed sender, uint256 amount);
    event ShipmentCancelled(uint256 indexed id);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier shipmentExists(uint256 id) {
        require(id < shipmentCount, "Shipment doesn't exist");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    //REGISTER AS COURIER
    function registerCourier(address courier) external onlyOwner {
        registeredCouriers[courier] = true;
    }

    //SENDER FUNCTIONS
    function createShipment(address _receiver, uint256 _deadline) external payable returns (uint256) {
        require(msg.value > 0, "Fee required");
        require(_receiver != address(0), "Invalid receiver");
        require(_deadline > block.timestamp, "Deadline time is not allowed");

        uint256 id = shipmentCount++;
        shipments[id] = Shipment({
            sender: msg.sender,
            receiver: _receiver,
            courier: address(0),
            fee: msg.value,
            deadline: _deadline,
            status: Status.Created,
            isPaid: false,
            isRefunded: false
        });

        addressToShipments[msg.sender].push(id);
        addressToShipments[_receiver].push(id);

        emit ShipmentCreated(id, msg.sender, _receiver, msg.value, _deadline);
        return id;   
    }

    function cancelShipment(uint256 id) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(msg.sender == s.sender, "Not sender");
        require(s.status == Status.Created, "Already picked up");

        s.status = Status.Cancelled;
        emit ShipmentCancelled(id);
    }

    //VULN 1: OWASP SC05 Reentrancy
    /* The external call (sending ETH back to msg.sender) happens *BEFORE*
     * the state is updated (s.refunded = true / fee = 0).
     * A malicious contract calling this function can re-enter
     * claimRefund() from its receive()/fallback() function and
     * drain the escrowed fee multiple times, taking funds that
     * belong to other shipments' senders and couriers.
     *
     * Fix (DON'T apply yet):
     *   BEFORE making the external call:
     *   set s.refunded = true
     *   and zero out s.fee
     *   or:
     *   set a reentrancy guard (nonReentrant modifier).
     *   swap out part 1 and 2 for fix
     */
    function claimRefund(uint256 id) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(msg.sender == s.sender, "Not sender");
        require(!s.isRefunded, "Already refunded");
        require(s.status == Status.Cancelled || (block.timestamp > s.deadline && s.status == Status.Confirmed),
        "Not elligible for refund");

        uint256 amount = s.fee;

        (bool success, ) = msg.sender.call{value: amount}("");  //part 1
        require(success, "Refund transfer failed");             //part 1

        s.isRefunded = true;                                    //part 2
        s.status = Status.Refunded;                             //part 2

        emit RefundClaimed(id, msg.sender, amount);
    }

    //VULN 2: OWASP SC01 Access Control
    
    /* This function is meant to be restricted to the logistics
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
        require(s.status == Status.Created, "Shipment already assigned to a courier");

        s.courier = courier;
        s.status = Status.Assigned;

        addressToShipments[courier].push(id);

        emit CourierAssigned(id, courier);
    }

    //COURIER FUNCTIONS (also contains OWASP SC01 Access Control Vulnerability)
    /* The functions here should check whether
     * `msg.sender == courier`
     * However that check is omitted intentionally,
     * which means any address can move shipment straight to Delivered
     * Easy fix, `require(msg.sender == s.courier, "Not assigned courier");`
    */
    function updateStatus(uint256 id, Status newStatus) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(
            newStatus == Status.PickedUp ||
            newStatus == Status.InTransit || 
            newStatus == Status.Delivered,
            "Invalid status change"
        );
        
        s.status = newStatus;
        emit StatusUpddated(id, newStatus);
    }

    //RECEIVER FUNCTIONS
    function confirmDelivery(uint256 id) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(msg.sender == s.receiver, "Not receiver");
        require(s.status == Status.Delivered, "Shipment not delivered");

        s.status = Status.Confirmed;
        emit DeliveryConfirmed(id);
    }

    //PAYMENT RELEASE
    function releasePayment(uint256 id) external shipmentExists(id) {
        Shipment storage s = shipments[id];
        require(s.status == Status.Confirmed, "Delivery not confirmed");
        require(!s.isPaid, "Already paid");
        require(msg.sender == s.courier, "Not assigned courier");

        uint256 amount = s.fee;
        s.isPaid = true;

        (bool success, ) = s.courier.call{value: amount}("");
        require(success, "Payment transfer failed");

        emit PaymentReleased(id, s.courier, amount);
    }

    //VIEW SHIPMENT
    function getShipment(uint256 id) external view shipmentExists(id) returns (Shipment memory) {
        return shipments[id];
    }
    function getShipmentsOf(address user) external view returns (uint256[] memory) {
        return addressToShipments[user];
    } 
    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}