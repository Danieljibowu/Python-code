"""
Insider Threat Risk Assessor - Extension Plus

Extension plus requirments:
- Secure admin login
- Haah the password using hashlib
- Audit date, time and username when risks are added or viewed
- Select controls from technical, legal/organisational and physical categories
- Generate two test cases with expected outcomes
- Save risk reports and audit evidence
"""

import hashlib
from datetime import datetime


# Classroom demonstration password.
# In a real system, passwords should never be hard-coded like this.
DEMO_ADMIN_PASSWORD = "Cyber123!"
STORED_PASSWORD_HASH = hashlib.sha256(
    DEMO_ADMIN_PASSWORD.encode("utf-8")
).hexdigest()


TECHNICAL_CONTROLS = [
    "Multi-factor authentication (MFA)",
    "Least-privilege access",
    "Audit logs and automated alerts",
    "USB/removable-media restrictions",
    "Account lockout and strong password rules"
]

LEGAL_ORGANISATIONAL_CONTROLS = [
    "Acceptable-use policy",
    "Data-protection training",
    "regular access reviews",
    "Incident-reporting procedure",
    "Joiner, mover and leaver account process"
]

PHYSICAL_CONTROLS = [
    "ID badges/access cards",
 "CCTV",
    "Locked server room",
    "Visitor sign-in log",
    "Clear desk and locked-screen policy"
]


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def login():
    print("=" * 70)
    print("SECURE ADMIN LOGIN")
    print("=" * 70)
    print("Classroom demo password: Cyber123!")
    print("(The program stores and comapres only the password hash.)\n")

    for attempt in range(3):
        username = input("Username: "). strip()
        password = input("Password: ")

        if username and hash_password(password) == STORED_PASSWORD_HASH:
            print("\nLogin successful.")
            write_audit_log(username, "logged in")
            return username

        attemps_left = 2 - attempt
        print(f"Login failed. Attempts remaining: {attempts_left}\n")

    print("Too many failed attempts. Access denied.")
    return None


def write_audit_log(username, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} | user={username} | action={action}\n"

    with open("audit_log.txt", "a", encoding="utf-8") as file:
        file.write(line)


def get_non_blank(prompt):
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Input cannot be blank.")


def get_choice(prompt, valid_choices):
    while True:
        value = input(prompt).strip().lower()
        if value in valid_choices:
            return value
        print ("Please choose from:", ", ".join(valid_choices))


def calculate_severity(probability, impact):
    probability_score = {
        "unlikely": 1,
        "likely": 2,
        "very likely": 3
    }

    impact_score = {
        "minor": 1,
        "moderate": 2,
        "major": 3
    }

    score = probability_score[probability] * impact_score[impact]

    if score <= 2:
        severity = "Low"
    elif score <= 4:
        severity = "Medium"
    elif score <= 6:
        severity = "High"
    else:
         severity = "Extreme"

    return score, severity


def choose_one_control(category_name, controls):
    print(f"\n{category_name} controls:")
    for number, control in enumerate(controls, start=1):
        print(f"{number}. {control}")

    while True:
        choice = input(f"Choose one {category_name.lower()} control:").strip()

        if choice.isdigit():
            choice = int(choice)
            if 1 <= choice <= len(controls):
                return controls[choice - 1]

            print("Please enter a valid number.")


def choose_controls():
    """
    The learner must select one control from each category.
    This demonstartes a balanced security plan.
    """
    technical = choose_one_control("Technical", TECHNICAL_CONTROLS)
    legal = choose_one_control(
        "legal/organisational",
        LEGAL_ORGANISATIONAL_CONTROLS
    )
    physical = choose_one_control("Physical", PHYSICAL_CONTROLS)

    return {
        "technical": technical,
        "legal": legal,
        "physical": physical
    }


def create_security_plan(title, severity, controls):
    return (
        f"The risk '{title}' has been assessed as {severity}. "
        f"The organisation should use {controls['technical']} as a technical control, "
        f"{controls['legal'].lower()} as a legal/organisational control, and "
        f"{controls['physical'].lower()} as a physical control. "
        "The technical measure reduces the opportunity for unauthorised activity, "
        "the organisational measure supports staff responsibilities and evidence, "
        "and the physical measure limits access to devices or secure areas. "
        "Together these controls provide defence in depth while still allowing "
        "authorised users to complete legitimate work."
    )


def generate_test_plan(risk) :
    """
    Automatically create two test cases that match the security plan.
    """
    return [
        {
            "test_no": 1,
            "description":
                f"Attempt the restricted action linked to '{risk['title']}' "
                "using an unauthorised account.",
            "expected_outcome":
                "Access is blocked or restricted, and the event is recorded in the audit log.",
            "further_action":
                "If access is allowed, review permissions and strengthen the technical control."
         },
        {
            "test_no": 2,
            "description":
                "Use an authorised account to complete a normal work task and check "
                "that the selected controls do not prevent legitimate use.",
            "expected_outcome":
                "The authorised task succeeds and relevant activity is logged correctly.",
            "further_action":
                "If normal work is blocked, adjust the control while keeping the risk reduced."
        }
    ]


def add_risk(username, risks):
    print("\n" + "=" * 70)
    print("ADD A SECURITY RISK")
    print("=" * 70)

    title = get_non_blank("Threat title: ")
    explanation = get_non_blank("Threat explanation: ")

    probability = get_choice(
        "Probability (unlikely / likely / very likely):",
        ["unlikely", "likely", "very likely"]
    )

    impact = get_choice(
        "Impact (minor / moderate / major): ",
        ["minor", "moderate", "major"]
    )

    score, severity = calculate_severity(probability, impact)
    controls = choose_controls()
    plan = create_security_plan(title, severity, controls)

    risk = {
        "title": title,
        "explanation": explanation,
        "probability": probability,
        "impact": impact,
        "score": score,
        "severity": severity,
        "controls": controls,
        "plan": plan
    }

    risk["test_plan"] = generate_test_plan(risk)
    risks.append(risk)

    write_audit_log(username, f"added risk: {title}")
    print("\nRisk added successfully.")


def display_risks(username, risks):
    write_audit_log(username, "viewec risk report")

    if not risks:
        print("\nThere are no stored risks yet.")
        return

    ranked = sorted(risks, key=lambda risk: risk["score"], reverse=True)

    print("\n" + "=" * 70)
    print("RANKED SECURITY RISK REPORT")
    print("=" * 70)

    for position, risk in enumerate(ranked, start=1):
        print(f"\n{position}. {risk['title']}")
        print("_" * 60)
        print("Explanation:", risk["explanation"])
        print("Probability:", risk["impact"].title())
        print("Impact:", risk["impact"].title())
        print("Score:", risk["score"])
        print("Severity:", risk["severity"])

        print("\nSelected controls:")
        print(" Technical:", risk["controls"]["technical]"])
        print(" Legal/organisational:", risk["controls"]["legal"])
        print(" Physical:", risk["controls"]["physical"])

        print("\nSecurity plan:")
        print(risk["plan"])

        print("\nTest plan:")
        for test in risk["test_plan"]:
            print(f" Test {test['test_no']}: {test['description']}")
            print(" Expected outcome:", test["expected_outcome"])
            print(" Further action:", test["further_action"])


def save (report_username, risk):
    ranked = sorted(risks, key=lambda risk: risk["score"], reverse=True)

    with open("extension_plus_security_report.txt", "w", emcoding="tuf-8") as file:
        file.write("EXTENSION PL,US SECURITY RISK REPORT\n")
        file.write("=" * 70 + "\n")

        for position, risk in enumerate(ranked, start=1) :
            file.write(f"\n{position}. {risk['title']}\n")
            file.write("-" * 60 + "\n")
            file.write(f"Explanation: {risk['explanation']}\n")
            file.write(f"Probability: {risk['probability'].title()}\n")
            file.write(f"Impact: {risk['impact'].title()}\n")
            file.write(f"Score: {risk['score']}\n")
            file.write(f"Severity: {risk['severity']}\n")

            file.write("\nSelected controls:\n")
            file.wirte(
                f"Technical: {risk['controls']['technical']}\n"
            )
            file.write(
                f"legal/organisational: {risk['controls']['legal']}\n"
            )
            file.write(
                f"Physical: {risk['controls']['physical']}\n"
            )

            file.write("\nSecurity plan:\n")
            file.write(risk["plan"] + "\n")

            file.write("\nTest plan:\n")
            for test in risk["test_plan"]:
                file.write(
                    f"Test {test['test_no']}: {test['description']}\n"
                )
                file.write(
                    f"Expected outcome: {test['expected_outcome']}\n"
                )
                file.write(
                    f"Further action: {test['further_action']}\n"
                )

    write_audit_log(username, "saved security report")
    print("\nReport saved as: extension_plus_security_report.txt")


def main():
    username = login()

    if username is None:
        return

    risks = []

    while True:
        print("\n" + "=" * 70)
        print("EXTENSION PLUS - MINI SECURITY TOOLKIT")
        print("=" * 70)
        print("1. Add risk")
        print("2. View ranked risks")
        print("3. Save report")
        print("4. Exit")

        choice = input("Choose an option: ").strip()

main()
