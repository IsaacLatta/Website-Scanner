<?php
// type_error.php

function sendEmail(string $to, string $subject): void {
    echo "Sending email to {$to} with subject {$subject}\n";
}

function main(): void {
    // Passing an array instead of string
    sendEmail(["not", "an", "email"], "Hello");
}

main();

