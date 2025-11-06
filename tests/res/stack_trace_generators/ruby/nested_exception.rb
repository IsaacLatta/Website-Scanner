# custom_error_nested.rb
class PaymentError < StandardError; end

def charge_card(amount_cents)
  raise PaymentError, "Declined payment for #{amount_cents} cents"
end

def process_order
  charge_card(5000)
end

def main
  process_order
end

main

