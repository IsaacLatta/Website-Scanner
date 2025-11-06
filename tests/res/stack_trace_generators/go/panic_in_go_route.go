package main

import (
    "fmt"
    "time"
)

func worker() {
    fmt.Println("worker starting")
    panic("panic inside goroutine")
}

func main() {
    go worker()
    // Give the goroutine time to run and panic
    time.Sleep(200 * time.Millisecond)
}

