# zero_division.rb
def divide(a, b)
  a / b
end

def main
  puts "About to divide by zero..."
  puts divide(10, 0)   # ZeroDivisionError
end

main

