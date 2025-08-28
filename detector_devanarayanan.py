import csv
import json
import re
import sys
from typing import Dict, Any, Tuple, List, Callable

class PiiScanner:
    def __init__(self, conf_path: str = "config.json"):
        print("Initializing PII Scanner...")
        self.conf = self._load_conf(conf_path)
        self._compile_regex()
        self.redactors = self._get_redactors()
        print("Scanner Ready. Rules loaded.")

    def _load_conf(self, path: str) -> Dict:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"FATAL: Config file not found at '{path}'.")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"FATAL: Invalid JSON in config file '{path}'.")
            sys.exit(1)

    def _compile_regex(self):
        for key, rule in self.conf['standalone_pii_patterns'].items():
            rule['compiled'] = re.compile(rule['regex'])

    def _get_redactors(self) -> Dict[str, Callable[[str], str]]:
        return {
            "mask_string": self._mask_str,
            "mask_email": self._mask_mail,
            "mask_numeric": self._mask_num,
        }

    def _mask_str(self, text: str) -> str:
        if not isinstance(text, str) or len(text) < 5: return "****"
        return f"{text[:2]}{'X' * (len(text) - 4)}{text[-2:]}"

    def _mask_mail(self, mail: str) -> str:
        try:
            user, domain = mail.split('@', 1)
            return f"{self._mask_str(user)}@{domain}"
        except (ValueError, AttributeError):
            return self._mask_str(str(mail))

    def _mask_num(self, num: str) -> str:
        return self._mask_str(str(num))

    def scan(self, rec: Dict[str, Any]) -> Tuple[Dict, bool, float, str]:
        safe_rec = rec.copy()
        score = 0.0
        log = []

        for pii_key, rule in self.conf['standalone_pii_patterns'].items():
            if pii_key in rec and isinstance(rec[pii_key], str):
                if rule['compiled'].fullmatch(rec[pii_key]):
                    score += rule['base_score']
                    log.append(f"found solo pii [{pii_key}]")
                    mask_fn = self.redactors[rule['redactor']]
                    safe_rec[pii_key] = mask_fn(rec[pii_key])

        combo_keys = set()
        for _, rule in self.conf['combinatorial_pii_sets'].items():
            keys_found = [k for k in rule['keys'] if k in rec]
            if len(keys_found) >= 2:
                score += rule['base_score'] * len(keys_found)
                log.append(f"found combo pii [{'+'.join(keys_found)}]")
                combo_keys.update(keys_found)

        for key in combo_keys:
            mask = self.conf['redaction_placeholders'].get(key)
            if mask in self.redactors:
                 safe_rec[key] = self.redactors[mask](rec[key])
            elif mask:
                safe_rec[key] = mask

        confidence = min(1.0, score)
        is_pii = confidence > 0.5
        reason = ", ".join(log) if log else "No PII detected"

        return safe_rec, is_pii, round(confidence, 2), reason

def main(in_file: str, out_file: str):
    scanner = PiiScanner()
    print(f"\nStarting PII scan on '{in_file}'...")

    try:
        with open(in_file, mode='r', encoding='utf-8') as i, \
             open(out_file, mode='w', encoding='utf-8', newline='') as o:

            reader = csv.DictReader(i)
            writer = csv.writer(o)
            writer.writerow(['record_id', 'redacted_data_json', 'is_pii', 'confidence_score', 'reason'])

            count = 0
            for row in reader:
                rec_id = row['record_id']
                json_str = row.get('data_json', '{}')
                try:
                    data = json.loads(json_str)
                    clean_data, is_pii, score, reason = scanner.scan(data)
                    writer.writerow([rec_id, json.dumps(clean_data), is_pii, score, reason])
                    count += 1
                except (json.JSONDecodeError, TypeError):
                    writer.writerow([rec_id, json_str, False, 0.0, "Data parsing error"])

            print(f"Scan complete. Processed {count} records.")
            print(f" sanitized output saved to '{out_file}'.")

    except FileNotFoundError:
        print(f"Error: The file '{in_file}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_devanarayanan.py <input_csv_file>")
        sys.exit(1)

    main(sys.argv[1], "redacted_output_devanarayanan.csv")