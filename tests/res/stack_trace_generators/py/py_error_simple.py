┌─(isaac@fedora)-[~/Projects/Website-Scanner/tests] module_refactor
└─$ cat > py_error_simple.py <<EOF def boom():
    return 1 / 0  # ZeroDivisionError


if __name__ == "__main__":
    boom()
