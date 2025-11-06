package main

import "fmt"

func main() {
    a := 10
    b := 0
    fmt.Println("About to divide by zero...")
    fmt.Println(a / b) // panic: runtime error: integer divide by zero
}

