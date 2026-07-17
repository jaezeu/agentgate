resource "aws_vpc" "sandbox" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "sandbox" {
  vpc_id = aws_vpc.sandbox.id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  count = 2

  availability_zone       = local.availability_zones[count.index]
  cidr_block              = var.public_subnet_cidrs[count.index]
  map_public_ip_on_launch = false
  vpc_id                  = aws_vpc.sandbox.id

  tags = {
    Name                                          = "${var.name_prefix}-public-${local.availability_zones[count.index]}"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = "1"
  }
}

resource "aws_subnet" "private" {
  count = 2

  availability_zone       = local.availability_zones[count.index]
  cidr_block              = var.private_subnet_cidrs[count.index]
  map_public_ip_on_launch = false
  vpc_id                  = aws_vpc.sandbox.id

  tags = {
    Name                                          = "${var.name_prefix}-private-${local.availability_zones[count.index]}"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.sandbox.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sandbox.id
  }

  tags = {
    Name = "${var.name_prefix}-public"
  }
}

resource "aws_route_table_association" "public" {
  count = 2

  route_table_id = aws_route_table.public.id
  subnet_id      = aws_subnet.public[count.index].id
}

resource "aws_eip" "nat" {
  domain = "vpc"

  depends_on = [aws_internet_gateway.sandbox]

  tags = {
    Name = "${var.name_prefix}-nat"
  }
}

resource "aws_nat_gateway" "sandbox" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  depends_on = [aws_internet_gateway.sandbox]

  tags = {
    Name = "${var.name_prefix}-nat"
  }
}

resource "aws_route_table" "private" {
  count = 2

  vpc_id = aws_vpc.sandbox.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.sandbox.id
  }

  tags = {
    Name = "${var.name_prefix}-private-${local.availability_zones[count.index]}"
  }
}

resource "aws_route_table_association" "private" {
  count = 2

  route_table_id = aws_route_table.private[count.index].id
  subnet_id      = aws_subnet.private[count.index].id
}
