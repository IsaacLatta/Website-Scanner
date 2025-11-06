package main

import "fmt"

type User struct {
    Name string
}

func main() {
    var u *User // nil
    fmt.Println("About to dereference nil pointer...")
    fmt.Println(u.Name) // panic: runtime error: invalid memory address or nil pointer dereference
}

