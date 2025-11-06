public class Helper {
    public static int parseAndDivide(String a, String b) {
        int x = Integer.parseInt(a);
        int y = Integer.parseInt(b);
        return x / y; // may throw ArithmeticException
    }
}

