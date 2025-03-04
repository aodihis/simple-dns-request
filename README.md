# Simple DNS Client

A simple DNS client written in Python that performs DNS queries.

## Usage

Run the script using the following command:

```sh
python app.py <DNS_SERVER> <DOMAIN>
```

Example:

```sh
python app.py 8.8.8.8 google.com
```

## Example Output

```
-------------------------------------------------------------------------------------------------
| name                                     | type | class | ttl   | data                       |
-------------------------------------------------------------------------------------------------
| forcesafesearch.google.com               | 5    | 1     | 41    | forcesafesearch.google.com |
| forcesafesearch.google.com               | 1    | 1     | 77208 | 216.239.38.120             |
-------------------------------------------------------------------------------------------------
```

## Requirements

- Python 3.x

## License

This project is licensed under the MIT License.
