<?php
// division_by_zero.php

function divide(int $a, int $b): int {
    return intdiv($a, $b); // intdiv throws DivisionByZeroError
}

function main(): void {
    echo "About to divide by zero...\n";
    echo divide(10, 0) . "\n";
}

main();

