#!/usr/bin/ruby1.9.1
# coding : utf-8

require "openssl"
require "optparse"
require "yaml"

# Orca Data Transfer
module OrcaDT
  class Signer
    def initialize(opts)
      @opts = opts
      @p12 = OpenSSL::PKCS12.new(
		File.read(@opts["CERT"]), @opts["PASS"])
    end
  
    def sign(path)
      signed_data = sign_data(@p12, File.read(path))
      signed_basename = File.basename(path) + ".p7m"
      signed_path = File.join(@opts["DIR"], signed_basename )
      File.open(signed_path, "w") { |io|
        io.write(signed_data)
      }
      puts "[SUCCESS] store #{signed_path}"
      if @opts["DEST"]
        scpdest = @opts["DEST"] + "/" + signed_basename
        scp(signed_path, scpdest)
        puts "[SUCCESS] upload #{scpdest}"
      end
    end
  
    def sign_data(p12, data)
      flag = OpenSSL::PKCS7::BINARY
      p7 = OpenSSL::PKCS7.sign(p12.certificate, p12.key, data, p12.ca_certs, flag)
      smime = OpenSSL::PKCS7.write_smime(p7, data)
      return smime
    end
  
    def scp(smimefile, scpdest)
      command = "scp #{smimefile} #{scpdest}"
      result = system(command)
      raise "exec failure : #{command}" unless result 
    end
  end
end

def parse_option(argv0, argv)
  config = nil
  parser = OptionParser.new{|opts|
    opts.banner = "Usage: #{File.basename(argv0)} [options]\n"
    opts.on_head("options:")
    opts.on("-c VAL", "", "config file") { |arg|
      config = arg
    }
    opts.on_tail('--help', 'show this message'){
      raise "help specified"
    }
  }
  begin
    parser.parse!(argv)
  rescue RuntimeError => ex
    puts parser;
    exit 1;
  end
  return config
end

if $0 == __FILE__
  config = parse_option($0, ARGV)
  unless config
    puts "specify -c"
    exit 1
  end

  begin
    opts = YAML.load_file(config)
    print "input passphrase:"
    opts["PASS"] = STDIN.gets.chomp!
    signer = OrcaDT::Signer.new(opts)
    ARGV.each{|filename|
      signer.sign(filename)
    }
  rescue Exception => ex
    puts "[ERROR] #{ex.message}"
    puts ex.backtrace
    exit 1
  end
  exit 0
end
