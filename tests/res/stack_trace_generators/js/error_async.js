async function bad() {
  throw new Error("async boom");
}

bad();
