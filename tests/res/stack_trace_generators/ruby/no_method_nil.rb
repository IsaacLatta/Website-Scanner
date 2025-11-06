# nil_no_method.rb
def fetch_user_name(user)
  user[:name]  # will blow up if user is nil
end

def main
  user = nil
  puts "About to fetch name from nil..."
  puts fetch_user_name(user)
end

main

