# missing_file.rb
def read_config(path)
  File.read(path)
end

def main
  # Path that shouldn't exist
  read_config("this_config_does_not_exist.yml")
end

main

