package main

func first() {
    second()
}

func second() {
    third()
}

func third() {
    panic("boom from third()")
}

func main() {
    first()
}

