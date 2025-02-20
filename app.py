import argparse
from dns_client import DNSClient

def print_table_fixed_width(data, col_widths=None):
    if not data:
        print("No data to display.")
        return

    headers = list(data[0].keys())

    # Calculate column widths if not provided
    if col_widths is None:
        col_widths = {}
        for header in headers:
            col_widths[header] = len(header)  # Start with header length
            for item in data:
                col_widths[header] = max(col_widths[header], len(str(item[header])))

        # Adjust width for "name" column
        col_widths["name"] = max(col_widths["name"], 40) # Set minimum width for name

    # Print header
    header_row = "| "
    for header in headers:
        header_row += "{:<{}} | ".format(header, col_widths[header])
    print("-" * len(header_row))
    print(header_row)
    print("-" * len(header_row))


    for item in data:
        row = "| "
        for header in headers:
            row += "{:<{}} | ".format(str(item[header]), col_widths[header])
        print(row)
    print("-" * len(header_row))


def main():
    parser = argparse.ArgumentParser(description='DNS Server Address')
    parser.add_argument('dns_server', type=str, help='The DNS server address')
    parser.add_argument('hostname', type=str, help='The hostname to resolve')
    args = parser.parse_args()

    dns_server_address = args.dns_server
    print(f'The DNS server address is: {dns_server_address}, and the hostname is: {args.hostname}')
    dns_client = DNSClient(dns_server_address)
    resolved = dns_client.resolve(args.hostname)

    print_table_fixed_width(resolved['answers'])

if __name__ == "__main__":
    main()