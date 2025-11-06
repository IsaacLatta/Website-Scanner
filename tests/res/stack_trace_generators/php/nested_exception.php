<?php
// nested_exception.php

class PaymentException extends Exception {}

function chargeCard(int $amountCents): void {
    throw new PaymentException("Declined payment for {$amountCents} cents");
}

function processOrder(): void {
    chargeCard(5000);
}

function main(): void {
    processOrder();
}

main();

