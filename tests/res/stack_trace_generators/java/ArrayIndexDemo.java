public class ArrayIndexDemo {
    public static void main(String[] args) {
        int[] nums = {1, 2, 3};
        // Deliberately out of bounds
        int x = nums[10];
        System.out.println(x);
    }
}

