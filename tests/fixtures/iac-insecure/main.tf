# 動作確認用。わざと危ない設定にしてある(実際の環境には使わない)。

resource "aws_s3_bucket" "example" {
  bucket = "kit-fixture-bucket"
}

resource "aws_security_group" "ssh_open" {
  name = "kit-fixture-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
