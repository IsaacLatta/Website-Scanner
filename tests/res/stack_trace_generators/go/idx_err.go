package main

import "fmt"

func main() {
    nums := []int{1, 2, 3}
    fmt.Println("Length:", len(nums))
    // Deliberately out of range
    fmt.Println(nums[10]) // panic: runtime error: index out of range [10] with length 3
}

