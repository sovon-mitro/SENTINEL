import re
import requests as rq


# ============================================================
# SENTINEL v0.1
# HTTP SECURITY & CVE CORRELATION SCANNER
# ============================================================


# ============================================================
# 0. NVD API
# ============================================================

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd(keyword):
    """
    Search the NVD database using a keyword.
    """

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20
    }

    response = rq.get(
        NVD_API_URL,
        params=params,
        timeout=10
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# 1. VERSION PROCESSING
# ============================================================

def parse_version(version_string):
    """
    Convert a version string such as:

        2.4.49

    into:

        [2, 4, 49]
    """

    return [
        int(part)
        for part in version_string.split(".")
    ]


def is_version_affected(
    detected_version,
    min_affected,
    max_affected
):
    """
    Check whether a detected version falls
    inside an affected version range.
    """

    try:
        current = parse_version(
            detected_version
        )

        minimum = parse_version(
            min_affected
        )

        maximum = parse_version(
            max_affected
        )

        return minimum <= current <= maximum

    except (ValueError, TypeError):
        return False


# ============================================================
# 2. NVD DATA EXTRACTION
# ============================================================

def extract_description(cve):
    """
    Extract the English CVE description.
    """

    descriptions = cve.get(
        "descriptions",
        []
    )

    for description in descriptions:

        if description.get("lang") == "en":
            return description.get(
                "value",
                "No description available."
            )

    return "No description available."


def extract_cvss(cve):
    """
    Extract CVSS v3.1 information.
    """

    metrics = cve.get(
        "metrics",
        {}
    )

    # --------------------------------------------------------
    # Prefer CVSS v3.1
    # --------------------------------------------------------

    v31 = metrics.get(
        "cvssMetricV31",
        []
    )

    if v31:

        cvss_data = v31[0].get(
            "cvssData",
            {}
        )

        return {
            "severity": cvss_data.get(
                "baseSeverity",
                "UNKNOWN"
            ),
            "score": cvss_data.get(
                "baseScore",
                "N/A"
            ),
            "vector": cvss_data.get(
                "vectorString",
                "N/A"
            )
        }

    # --------------------------------------------------------
    # Fallback to CVSS v3.0
    # --------------------------------------------------------

    v30 = metrics.get(
        "cvssMetricV30",
        []
    )

    if v30:

        cvss_data = v30[0].get(
            "cvssData",
            {}
        )

        return {
            "severity": cvss_data.get(
                "baseSeverity",
                "UNKNOWN"
            ),
            "score": cvss_data.get(
                "baseScore",
                "N/A"
            ),
            "vector": cvss_data.get(
                "vectorString",
                "N/A"
            )
        }

    # --------------------------------------------------------
    # No supported CVSS data
    # --------------------------------------------------------

    return {
        "severity": "UNKNOWN",
        "score": "N/A",
        "vector": "N/A"
    }


def extract_cve_data(cve):
    """
    Convert raw NVD CVE data into a
    simplified SENTINEL finding.
    """

    cve_id = cve.get(
        "id",
        "UNKNOWN"
    )

    cvss = extract_cvss(cve)

    return {
        "cve_id": cve_id,
        "severity": cvss["severity"],
        "score": cvss["score"],
        "vector": cvss["vector"],
        "description": extract_description(cve)
    }


# ============================================================
# 3. NVD AFFECTED-VERSION MATCHING
# ============================================================

def extract_affected_versions(cve):
    """
    Extract affected software/version information
    from NVD CPE configuration data.
    """

    affected_versions = []

    configurations = cve.get(
        "configurations",
        []
    )

    for configuration in configurations:

        nodes = configuration.get(
            "nodes",
            []
        )

        for node in nodes:

            cpe_matches = node.get(
                "cpeMatch",
                []
            )

            for cpe in cpe_matches:

                # Ignore non-vulnerable CPE entries
                if not cpe.get(
                    "vulnerable",
                    False
                ):
                    continue

                criteria = cpe.get(
                    "criteria",
                    ""
                )

                parts = criteria.split(":")

                # A CPE should contain enough
                # components to identify product/version.
                if len(parts) < 6:
                    continue

                product = parts[4]
                version = parts[5]

                affected_versions.append(
                    {
                        "product": product,
                        "version": version,

                        "versionStartIncluding":
                            cpe.get(
                                "versionStartIncluding"
                            ),

                        "versionStartExcluding":
                            cpe.get(
                                "versionStartExcluding"
                            ),

                        "versionEndIncluding":
                            cpe.get(
                                "versionEndIncluding"
                            ),

                        "versionEndExcluding":
                            cpe.get(
                                "versionEndExcluding"
                            )
                    }
                )

    return affected_versions


def version_matches_cpe(
    detected_version,
    affected_version
):
    """
    Determine whether the detected version
    matches an NVD affected-version entry.
    """

    exact_version = affected_version.get(
        "version"
    )

    # --------------------------------------------------------
    # Exact version match
    # --------------------------------------------------------

    if (
        exact_version
        and exact_version != "*"
    ):

        if exact_version == detected_version:
            return True

    # --------------------------------------------------------
    # Version range match
    # --------------------------------------------------------

    try:

        current = parse_version(
            detected_version
        )

        start_including = affected_version.get(
            "versionStartIncluding"
        )

        start_excluding = affected_version.get(
            "versionStartExcluding"
        )

        end_including = affected_version.get(
            "versionEndIncluding"
        )

        end_excluding = affected_version.get(
            "versionEndExcluding"
        )

        # ----------------------------------------------------
        # Minimum boundary
        # ----------------------------------------------------

        if start_including:

            if current < parse_version(
                start_including
            ):
                return False

        if start_excluding:

            if current <= parse_version(
                start_excluding
            ):
                return False

        # ----------------------------------------------------
        # Maximum boundary
        # ----------------------------------------------------

        if end_including:

            if current > parse_version(
                end_including
            ):
                return False

        if end_excluding:

            if current >= parse_version(
                end_excluding
            ):
                return False

        # ----------------------------------------------------
        # If at least one range boundary exists,
        # the version is inside the range.
        # ----------------------------------------------------

        if (
            start_including
            or start_excluding
            or end_including
            or end_excluding
        ):
            return True

    except (
        ValueError,
        TypeError
    ):
        pass

    return False


def cve_affects_target(
    cve,
    detected_product,
    detected_version
):
    """
    Determine whether a CVE actually affects
    the detected product and version.
    """

    affected_versions = (
        extract_affected_versions(cve)
    )

    detected_product = (
        detected_product.lower()
    )

    for affected in affected_versions:

        cpe_product = (
            affected["product"].lower()
        )

        # ----------------------------------------------------
        # Product comparison
        # ----------------------------------------------------

        if (
            detected_product not in cpe_product
            and cpe_product not in detected_product
        ):
            continue

        # ----------------------------------------------------
        # Version comparison
        # ----------------------------------------------------

        if version_matches_cpe(
            detected_version,
            affected
        ):
            return True

    return False


def find_nvd_vulnerabilities(
    detected_product,
    detected_version
):
    """
    Search NVD and return only CVEs that
    actually affect the detected product/version.
    """

    keyword = (
        f"{detected_product} "
        f"{detected_version}"
    )

    try:

        data = query_nvd(
            keyword
        )

    except rq.exceptions.RequestException as e:

        print(
            f"[!] NVD request failed: {e}"
        )

        return []

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    findings = []

    for item in vulnerabilities:

        cve = item.get(
            "cve"
        )

        if not cve:
            continue

        # ----------------------------------------------------
        # Keyword search alone is NOT enough.
        # Verify the affected product/version.
        # ----------------------------------------------------

        if not cve_affects_target(
            cve,
            detected_product,
            detected_version
        ):
            continue

        finding = extract_cve_data(
            cve
        )

        findings.append(
            finding
        )

    return findings


# ============================================================
# 4. HTTP SCANNER
# ============================================================

def scan_url(url_to_scan):
    """
    Send an HTTP request and collect
    basic server information.
    """

    try:

        response = rq.get(
            url_to_scan,
            timeout=5
        )

        return {
            "URL": response.url,

            "status": "success",

            "status_code":
                response.status_code,

            "server":
                response.headers.get(
                    "server"
                ),

            "content_type":
                response.headers.get(
                    "content-type"
                ),

            "error_type": None,

            "error_message": None
        }

    except rq.exceptions.Timeout as e:

        return {
            "URL": url_to_scan,
            "status": "failed",
            "status_code": None,
            "server": None,
            "content_type": None,
            "error_type": "timeout",
            "error_message": str(e)
        }

    except rq.exceptions.ConnectionError as e:

        return {
            "URL": url_to_scan,
            "status": "failed",
            "status_code": None,
            "server": None,
            "content_type": None,
            "error_type": "connection_error",
            "error_message": str(e)
        }

    except rq.exceptions.RequestException as e:

        return {
            "URL": url_to_scan,
            "status": "failed",
            "status_code": None,
            "server": None,
            "content_type": None,
            "error_type": "request_error",
            "error_message": str(e)
        }


# ============================================================
# 5. RESPONSE ANALYZER
# ============================================================

def analyze_response(response_dict):

    server_header = response_dict.get(
        "server"
    )

    url = response_dict.get(
        "URL"
    )

    # --------------------------------------------------------
    # Request failed
    # --------------------------------------------------------

    if response_dict.get(
        "status"
    ) == "failed":

        return {
            "url": url,
            "product": "unknown",
            "version": "unknown",
            "status": "failed",
            "findings": [],

            "error_type":
                response_dict.get(
                    "error_type"
                ),

            "error_message":
                response_dict.get(
                    "error_message"
                )
        }

    # --------------------------------------------------------
    # Server header missing
    # --------------------------------------------------------

    if not server_header:

        return {
            "url": url,
            "product": "unknown",
            "version": "unknown",
            "status": "success",
            "findings": [],
            "error_type":
                "server_header_missing",
            "error_message":
                "Server header was not provided."
        }

    # --------------------------------------------------------
    # Extract Product/Version
    #
    # Example:
    #
    # Apache/2.4.49
    # nginx/1.31.4
    # --------------------------------------------------------

    parts = server_header.split(
        "/"
    )

    if len(parts) < 2:

        return {
            "url": url,
            "product": server_header,
            "version": "unknown",
            "status": "success",
            "findings": [],
            "error_type":
                "version_not_detected",
            "error_message":
                "Could not extract product/version "
                "from Server header."
        }

    product = parts[0].strip()

    version = parts[1].strip()

    # --------------------------------------------------------
    # Validate version format
    # --------------------------------------------------------

    version_pattern = (
        r"^\d+\.\d+\.\d+$"
    )

    if not re.match(
        version_pattern,
        version
    ):

        return {
            "url": url,
            "product": product,
            "version": "unknown",
            "status": "success",
            "findings": [],
            "error_type":
                "invalid_version_format",
            "error_message":
                f"Could not parse version from "
                f"server header: {server_header}"
        }

    # --------------------------------------------------------
    # Search NVD
    # --------------------------------------------------------

    print(
        f"[+] Searching NVD for "
        f"{product}/{version}..."
    )

    vulnerabilities = (
        find_nvd_vulnerabilities(
            product,
            version
        )
    )

    return {
        "url": url,
        "product": product,
        "version": version,
        "status": "success",
        "findings": vulnerabilities,
        "error_type": None,
        "error_message": None
    }


# ============================================================
# 6. REPORT GENERATOR
# ============================================================

def generate_report(
    analysis_results
):

    print("\n")

    print("=" * 70)

    print(
        "              SENTINEL v0.1 SECURITY REPORT"
    )

    print("=" * 70)

    for result in analysis_results:

        print(
            "\n" + "-" * 70
        )

        print(
            f"Target      : "
            f"{result['url']}"
        )

        print(
            f"Technology  : "
            f"{result['product']}"
        )

        print(
            f"Version     : "
            f"{result['version']}"
        )

        print(
            f"Status      : "
            f"{result['status']}"
        )

        print(
            "-" * 70
        )

        # ----------------------------------------------------
        # Failed request
        # ----------------------------------------------------

        if result["status"] == "failed":

            print(
                "[!] Scan failed"
            )

            print(
                f"    Error type : "
                f"{result['error_type']}"
            )

            print(
                f"    Message    : "
                f"{result['error_message']}"
            )

            continue

        # ----------------------------------------------------
        # Findings
        # ----------------------------------------------------

        findings = result[
            "findings"
        ]

        if not findings:

            print(
                "[+] No matching vulnerabilities "
                "identified by NVD."
            )

            continue

        # ----------------------------------------------------
        # Print findings
        # ----------------------------------------------------

        for finding in findings:

            print(
                "\n[!] VULNERABILITY FOUND"
            )

            print(
                f"    CVE         : "
                f"{finding['cve_id']}"
            )

            print(
                f"    Severity    : "
                f"{finding['severity']}"
            )

            print(
                f"    CVSS Score  : "
                f"{finding['score']}"
            )

            print(
                f"    CVSS Vector : "
                f"{finding['vector']}"
            )

            print(
                f"    Description : "
                f"{finding['description']}"
            )

    print(
        "\n" + "=" * 70
    )

    print(
        "                    END OF REPORT"
    )

    print(
        "=" * 70
    )


# ============================================================
# 7. USER INPUT
# ============================================================

def get_target():

    print(
        "\n" + "=" * 70
    )

    print(
        "                    SENTINEL v0.1"
    )

    print(
        "          HTTP SECURITY & CVE SCANNER"
    )

    print(
        "=" * 70
    )

    target = input(
        "\nEnter target URL or IP address: "
    ).strip()

    if not target:

        print(
            "[!] No target provided."
        )

        return None

    # --------------------------------------------------------
    # Automatically add HTTP when the user
    # enters only a domain/IP.
    # --------------------------------------------------------

    if not target.startswith(
        (
            "http://",
            "https://"
        )
    ):

        target = (
            "http://" + target
        )

    return target


# ============================================================
# 8. MAIN ENGINE
# ============================================================

def main():

    target = get_target()

    if target is None:
        return

    print(
        f"\n[+] Target: {target}"
    )

    print(
        "[+] Starting SENTINEL scan..."
    )

    # --------------------------------------------------------
    # Scanner
    # --------------------------------------------------------

    scan_data = scan_url(
        target
    )

    # --------------------------------------------------------
    # Analyzer + NVD correlation
    # --------------------------------------------------------

    analysis = analyze_response(
        scan_data
    )

    # --------------------------------------------------------
    # Reporter
    # --------------------------------------------------------

    generate_report(
        [analysis]
    )


# ============================================================
# 9. PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()