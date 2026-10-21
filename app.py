
import hmac
import math
import os
import random
import secrets
from pathlib import Path

from flask import Flask, abort, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_HTTPS_ONLY") == "1"
)
secret_key_path = Path(__file__).with_name("secret.key")
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    if not secret_key_path.exists():
        secret_key_path.write_bytes(secrets.token_bytes(32))
    app.secret_key = secret_key_path.read_bytes().strip()

# 1. LOGIN ACCOUNTS
accounts = {
    "admin": {
        "password": generate_password_hash("Campus@123"),
        "role": "admin"
    },
    "S001": {
        "password": generate_password_hash("Campus@123"),
        "role": "student"
    }
}

# 2. MIDTERM USER RECORDS
users = {
    "S001": {"name": "Maria Santos", "category": "Student", "active": True},
    "S002": {"name": "Juan Dela Cruz", "category": "Student", "active": True},
    "S003": {"name": "Ana Reyes", "category": "Student", "active": True},
    "S004": {"name": "Pedro Garcia", "category": "Student", "active": False},
    "F001": {"name": "Dr. Cruz", "category": "Faculty", "active": True},
    "F002": {"name": "Prof. Santos", "category": "Faculty", "active": True},
    "ST001": {"name": "Mr. Lopez", "category": "Staff", "active": True},
    "ST002": {"name": "Ms. Reyes", "category": "Staff", "active": False},
    "V001": {"name": "Visitor One", "category": "Visitor", "active": True},
    "V002": {"name": "Visitor Two", "category": "Visitor", "active": False}
}

authorized_users = {"S001", "S002", "S003", "F001", "F002", "ST001"}
restricted_users = {"S004", "V002"}

facilities = [
    "Computer Laboratory",
    "Library",
    "Science Laboratory",
    "Student Lounge"
]
access_relation = {
    "S001": {"Computer Laboratory", "Library", "Student Lounge"},
    "S002": {"Computer Laboratory", "Library", "Student Lounge"},
    "S003": {"Library", "Student Lounge"},
    "S004": set(),
    "F001": set(facilities),
    "F002": {"Computer Laboratory", "Library", "Science Laboratory"},
    "ST001": {"Computer Laboratory", "Library"},
    "ST002": set(),
    "V001": {"Library"},
    "V002": set()
}

# 3. ACCESS MATRIX
def create_matrix():
    matrix = []

    for user_id in users:
        row = []

        for facility in facilities:
            if facility in access_relation[user_id]:
                row.append(1)
            else:
                row.append(0)

        matrix.append(row)

    return matrix


# 4. CHECK FACILITY ACCESS
def check_access(user_id, facility):
    if user_id not in users:
        return False, "User does not exist."

    if not users[user_id]["active"]:
        return False, "Account is inactive."

    if user_id not in authorized_users:
        return False, "User is not authorized."

    if facility not in access_relation[user_id]:
        return False, "No permission for this facility."

    return True, "Access granted."


# 5. CAMPUS NAVIGATION GRAPH
campus_graph = {
    "Main Gate": {"Library": 2, "Administration": 3},
    "Library": {"Main Gate": 2, "Science Laboratory": 2},
    "Administration": {"Main Gate": 3, "Computer Laboratory": 2},
    "Computer Laboratory": {"Administration": 2, "Science Laboratory": 3},
    "Science Laboratory": {"Library": 2, "Computer Laboratory": 3,
                           "Student Lounge": 2},
    "Student Lounge": {"Science Laboratory": 2}
}


# Dijkstra's algorithm finds the route with the lowest total edge cost.
def find_route(start, goal):
    if start not in campus_graph or goal not in campus_graph:
        return []

    distances = {location: math.inf for location in campus_graph}
    previous = {}
    unvisited = list(campus_graph)
    distances[start] = 0

    while unvisited:
        current = min(unvisited, key=lambda location: distances[location])
        if distances[current] == math.inf:
            break
        if current == goal:
            break

        unvisited.remove(current)
        for neighbor, cost in campus_graph[current].items():
            new_distance = distances[current] + cost
            if neighbor in unvisited and new_distance < distances[neighbor]:
                distances[neighbor] = new_distance
                previous[neighbor] = current

    if distances[goal] == math.inf:
        return []

    route = [goal]
    while route[-1] != start:
        route.append(previous[route[-1]])
    route.reverse()
    return route


# 6. FACILITY MONITORING
# These manually managed statuses are separate from probability simulation.
facility_status = {
    "Computer Laboratory": {
        "status": "Available",
        "note": "Ready for student use"
    },
    "Library": {
        "status": "Available",
        "note": "Open for studying"
    },
    "Science Laboratory": {
        "status": "Under Maintenance",
        "note": "Equipment maintenance in progress"
    },
    "Student Lounge": {
        "status": "Available",
        "note": "Open for students"
    }
}


# 7. CAESAR CIPHER
def caesar_cipher(message, shift):
    result = []
    for character in message:
        if "A" <= character <= "Z":
            first_letter = ord("A")
        elif "a" <= character <= "z":
            first_letter = ord("a")
        else:
            result.append(character)
            continue

        shifted = (ord(character) - first_letter + shift) % 26
        result.append(chr(first_letter + shifted))

    return "".join(result)


# 8. CAMPUS TREE AND RECURSION
campus_tree = {
    "Campus": {
        "Academic Buildings": {
            "Computer Laboratory": {},
            "Science Laboratory": {}
        },
        "Other Facilities": {
            "Library": {},
            "Student Lounge": {}
        }
    }
}


def show_tree(tree, level=0):
    result = []

    for name, children in tree.items():
        result.append({"name": name, "level": level})
        result.extend(show_tree(children, level + 1))

    return result


# 9. FINITE STATE MACHINE
states = {
    "Login": {"success": "Access Granted", "failure": "Access Denied"},
    "Access Granted": {"navigate": "Navigating", "logout": "Login"},
    "Access Denied": {"retry": "Login", "logout": "Login"},
    "Navigating": {"arrive": "Monitoring", "logout": "Login"},
    "Monitoring": {"navigate": "Navigating", "logout": "Login"}
}


def is_admin():
    return session.get("role") == "admin"


@app.context_processor
def inject_csrf_token():
    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return session["csrf_token"]

    return {"csrf_token": csrf_token}


@app.before_request
def validate_csrf_token():
    if request.method == "POST":
        form_token = request.form.get("csrf_token", "")
        session_token = session.get("csrf_token", "")
        if not form_token or not hmac.compare_digest(form_token, session_token):
            abort(400)


# 10. LOGIN PAGE
@app.route("/", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        session.clear()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username in accounts:
            saved_password = accounts[username]["password"]

            if check_password_hash(saved_password, password):
                session["username"] = username
                session["role"] = accounts[username]["role"]

                if session["role"] == "admin":
                    return redirect(url_for("admin_dashboard"))

                return redirect(url_for("student_dashboard"))

        error = "Incorrect username or password."

    return render_template("login.html", error=error)


# 11. ADMIN DASHBOARD
@app.route("/admin")
def admin_dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    if not is_admin():
        abort(403)

    return render_template(
        "dashboard.html",
        users=users,
        authorized=len(authorized_users),
        restricted=len(restricted_users),
        facilities=len(facilities)
    )


# 12. STUDENT DASHBOARD
@app.route("/student")
def student_dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "student":
        abort(403)

    username = session["username"]
    authorized_facilities = sorted(access_relation.get(username, set()))

    return render_template(
        "student_dashboard.html",
        student_name=users[username]["name"],
        authorized_facilities=authorized_facilities,
        available_count=sum(
            1 for details in facility_status.values()
            if details["status"] == "Available"
        ),
        facility_status=facility_status,
        facilities=facilities
    )


# 13. USER SEARCH AND SORT
@app.route("/users")
def users_page():
    if "username" not in session:
        return redirect(url_for("login"))
    if not is_admin():
        abort(403)

    keyword = request.args.get("q", "").strip().lower()
    sort_by = request.args.get("sort", "id")

    results = []

    for user_id, user in users.items():
        if keyword in user_id.lower() or keyword in user["name"].lower():
            results.append({"id": user_id, **user})

    if sort_by == "name":
        results.sort(key=lambda user: user["name"].lower())
    else:
        results.sort(key=lambda user: user["id"])

    return render_template("users.html", results=results,
                           keyword=keyword, sort_by=sort_by)


# 14. ACCESS VERIFICATION
@app.route("/check-access", methods=["GET", "POST"])
def access_page():
    if "username" not in session:
        return redirect(url_for("login"))

    available_users = users
    if session.get("role") == "student":
        username = session["username"]
        available_users = {username: users[username]}

    result = None

    if request.method == "POST":
        if session.get("role") == "student":
            user_id = session["username"]
        else:
            user_id = request.form.get("user_id", "")
        facility = request.form.get("facility", "")
        if user_id not in users or facility not in facilities:
            result = {
                "granted": False,
                "user_id": user_id,
                "facility": facility,
                "reason": "Choose a valid user and campus facility."
            }
        else:
            granted, reason = check_access(user_id, facility)
            result = {
                "granted": granted,
                "user_id": user_id,
                "facility": facility,
                "reason": reason
            }

    return render_template("access.html", users=available_users,
                           facilities=facilities, result=result)


# 15. RELATIONS
@app.route("/relation")
def relation_page():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("relation.html",
                           users=users,
                           access_relation=access_relation)


# 16. ACCESS MATRIX
@app.route("/matrix")
def matrix_page():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("matrix.html",
                           user_ids=list(users.keys()),
                           facility_names=facilities,
                           matrix=create_matrix())


# 17. CAMPUS NAVIGATION
@app.route("/navigation", methods=["GET", "POST"])
def navigation_page():
    if "username" not in session:
        return redirect(url_for("login"))

    locations = list(campus_graph.keys())
    route = []
    error = ""

    start = locations[0]
    goal = locations[-1]

    if request.method == "POST":
        start = request.form.get("start", "")
        goal = request.form.get("goal", "")

        if start in campus_graph and goal in campus_graph:
            route = find_route(start, goal)
        else:
            error = "Choose a valid starting location and destination."

    total_cost = sum(
        campus_graph[first][second]
        for first, second in zip(route, route[1:])
    )

    return render_template("navigation.html",
                           locations=locations,
                           start=start,
                           goal=goal,
                           route=route,
                           total_cost=total_cost,
                           error=error,
                           graph=campus_graph)


# 18. FACILITY MONITORING
@app.route("/monitoring", methods=["GET", "POST"])
def monitoring_page():
    if "username" not in session:
        return redirect(url_for("login"))

    message = ""
    if request.method == "POST":
        if not is_admin():
            message = "Only an administrator can update facility statuses."
        else:
            facility = request.form.get("facility", "")
            status = request.form.get("status", "")
            note = request.form.get("note", "").strip()
            allowed_statuses = {
                "Available", "Full", "Closed", "Under Maintenance"
            }
            default_notes = {
                "Available": "Ready for use.",
                "Full": "Currently at capacity.",
                "Closed": "Not open for use.",
                "Under Maintenance": "Temporarily unavailable for maintenance."
            }

            if facility not in facilities or status not in allowed_statuses:
                message = "Choose a valid facility and status."
            elif len(note) > 200:
                message = "Status details must be 200 characters or fewer."
            else:
                facility_status[facility]["status"] = status
                facility_status[facility]["note"] = note or default_notes[status]
                message = "Facility status updated."

    return render_template(
        "monitoring.html",
        facilities=facilities,
        facility_status=facility_status,
        admin=is_admin(),
        message=message
    )


# 19. CAESAR CIPHER
@app.route("/security", methods=["GET", "POST"])
def security_page():
    error = ""
    result = ""
    action = ""
    message = ""
    shift = 3

    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        message = request.form.get("message", "")
        action = request.form.get("action", "")
        try:
            shift = int(request.form.get("shift", ""))
        except ValueError:
            error = "Choose a shift from 1 to 25."

        if not error and not message.strip():
            error = "Enter a message to process."
        elif not error and len(message) > 5000:
            error = "Messages must be 5000 characters or fewer."
        elif not error and not 1 <= shift <= 25:
            error = "Choose a shift from 1 to 25."
        elif not error and action == "encrypt":
            result = caesar_cipher(message, shift)
        elif not error and action == "decrypt":
            result = caesar_cipher(message, -shift)
        elif not error:
            error = "Choose a valid message action."

    return render_template(
        "security.html",
        encrypted_message=result if action == "encrypt" and not error else "",
        decrypted_message=result if action == "decrypt" and not error else "",
        error=error,
        message=message,
        shift=shift
    )


# 20. CAMPUS TREE
@app.route("/campus-tree")
def campus_tree_page():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("campus_tree.html",
                           tree_rows=show_tree(campus_tree))


# 21. PROBABILITY SIMULATION
@app.route("/simulation", methods=["GET", "POST"])
def simulation_page():
    if "username" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":
        try:
            trials = int(request.form.get("trials", ""))

            if not 1 <= trials <= 10000:
                raise ValueError

            available = 0

            for _ in range(trials):
                if random.choice([True, False]):
                    available += 1

            result = {
                "trials": trials,
                "available": available,
                "unavailable": trials - available,
                "probability": available / trials
            }

        except ValueError:
            result = {"error": "Enter a number from 1 to 10000."}

    return render_template("simulation.html", result=result)


# 22. NUMBER THEORY
@app.route("/number-theory", methods=["GET", "POST"])
def number_theory_page():
    if "username" not in session:
        return redirect(url_for("login"))

    number = 2
    error = ""
    if request.method == "POST":
        try:
            number = int(request.form.get("number", ""))
            if not 1 <= number <= 999999:
                raise ValueError
        except ValueError:
            number = 2
            error = "Enter a whole number from 1 to 999999."

    return render_template("number_theory.html",
                           number=number,
                           remainder=number % 7,
                           gcd=math.gcd(number, 7),
                           is_coprime=math.gcd(number, 7) == 1,
                           error=error)


# 23. LOGIC AND PROOF
@app.route("/logic")
def logic_page():
    if "username" not in session:
        return redirect(url_for("login"))

    return render_template("logic.html")


# 24. FINITE STATE MACHINE EXPLANATION
@app.route("/fsm", methods=["GET", "POST"])
def fsm_page():
    if "username" not in session:
        return redirect(url_for("login"))

    current_state = "Login"
    event = ""
    next_state = ""
    previous_state = ""
    message = "Choose an event to see the next state."
    if request.method == "POST":
        current_state = request.form.get("current_state", "")
        event = request.form.get("event", "")
        if current_state in states and event in states[current_state]:
            previous_state = current_state
            current_state = states[current_state][event]
            next_state = current_state
            message = f"{previous_state} + {event} -> {next_state}"
        else:
            current_state = "Login"
            event = ""
            message = "Choose a valid state and event."

    return render_template(
        "fsm.html",
        states=states,
        current_state=current_state,
        previous_state=previous_state,
        event=event,
        next_state=next_state,
        message=message
    )


# 25. LOGOUT
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

# ============================================================
# FACILITY MONITORING ROUTE
# ============================================================
if __name__ == "__main__":
    app.run()
