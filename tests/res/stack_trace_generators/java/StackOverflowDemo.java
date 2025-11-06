public class StackOverflowDemo {

    public static void main(String[] args) {
        recurse(0);
    }

    static void recurse(int n) {
        // Just keep recursing until the stack blows
        recurse(n + 1);
    }
}

