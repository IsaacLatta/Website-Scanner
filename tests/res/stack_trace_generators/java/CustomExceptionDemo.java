class MyCustomException extends RuntimeException {
    public MyCustomException(String message) {
        super(message);
    }
}

public class CustomExceptionDemo {

    public static void main(String[] args) {
        first();
    }

    static void first() {
        second();
    }

    static void second() {
        third();
    }

    static void third() {
        throw new MyCustomException("Boom from third()");
    }
}

