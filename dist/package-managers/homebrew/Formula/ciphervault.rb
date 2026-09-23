class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.12"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.12/ciphervault-v1.0.12-aarch64-apple-darwin.tar.gz"
      sha256 "9c2f30fcded7e7dbaff42d767de0827dcbb6bbb7d1e8fe7605055de27be27363"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.12/ciphervault-v1.0.12-x86_64-apple-darwin.tar.gz"
      sha256 "d924b93079e08df4c1579e358794ab265ea42f568b75428b4e30e9233becdec7"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.12/ciphervault-v1.0.12-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "2d50de09b0a3cbfda762c41ad5aeb0f58c488dfaa7faac3df1b55f5cbae07222"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.12/ciphervault-v1.0.12-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7e703a89c4a6ed3c9d64e6506cd185c54b413cf7f55aa671d54ef941299f3a78"
    end
  end

  def install
    bin.install "bin/ciphervault"
    bin.install "bin/ciphervault-operator"
    bin.install "bin/ciphervault-agent"
    bin.install "bin/ciphervault-maintenance"

    if Dir.exist?("config")
      (etc/"ciphervault").install Dir["config/*"]
    end
  end

  def caveats
    <<~EOS
      Quick Start:
        ciphervault init
        ciphervault track .env
        ciphervault push -m "Initial commit"
        ciphervault diff
        ciphervault run -- npm start
        ciphervault peers
    EOS
  end

  test do
    assert_match "Decentralized, encrypted version control", shell_output("#{bin}/ciphervault --help")
  end
end
