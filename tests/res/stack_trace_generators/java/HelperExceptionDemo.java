public class HelperExceptionDemo {
    public static void main(String[] args) {
        // Second argument is zero -> ArithmeticException: / by zero
        int result = Helper.parseAndDivide("10", "0");
        System.out.println(result);
    }
}

