# wrong_arity.rb
def send_email(to, subject)
  puts "Sending email to #{to} with subject #{subject}"
end

def main
  # Missing the subject argument
  send_email("user@example.com")
end

main

