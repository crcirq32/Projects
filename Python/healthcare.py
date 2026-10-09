from dataclasses import dataclass
from typing import List

#BMI reference indicator — 20% weight
#Blood-pressure follow-up indicator — 20% weight
#A1C follow-up indicator — 20% weight
#Smoking-status indicator — 20% weight
#Data-completeness score — 20% weight


@dataclass
class Person:
    name: str
    age: int
    height_cm: float
    weight_kg: float
    smoker: bool
    systolic_bp: int
    diastolic_bp: int
    a1c_percent: float
    chronic_conditions: List[str]


def clamp(value: float, low: float = 0, high: float = 100) -> float:
    return max(low, min(high, value))


def bmi(height_cm: float, weight_kg: float) -> float:
    height_m = height_cm / 100
    return weight_kg / (height_m * height_m)


def bmi_indicator(value: float) -> float:
    """
    100 means closer to the selected reference interval.
    This is not a measure of health, fitness, or worth.
    """
    if 18.5 <= value < 25:
        return 100.0
    if 25 <= value < 30:
        return 75.0
    if 30 <= value < 35:
        return 50.0
    if value >= 35:
        return 25.0
    return 50.0


def blood_pressure_indicator(systolic: int, diastolic: int) -> float:
    if systolic < 120 and diastolic < 80:
        return 100.0
    if systolic < 130 and diastolic < 80:
        return 80.0
    if systolic < 140 and diastolic < 90:
        return 60.0
    return 30.0


def a1c_indicator(a1c: float) -> float:
    if a1c < 5.7:
        return 100.0
    if a1c < 6.5:
        return 60.0
    return 30.0


def smoking_indicator(smoker: bool) -> float:
    return 30.0 if smoker else 100.0


def data_completeness_indicator(person: Person) -> float:
    fields = [
        person.age,
        person.height_cm,
        person.weight_kg,
        person.systolic_bp,
        person.diastolic_bp,
        person.a1c_percent,
        person.chronic_conditions,
    ]

    present = sum(
        value is not None and value != ""
        for value in fields
    )

    return round((present / len(fields)) * 100, 1)


def evaluate(person: Person) -> dict:
    person_bmi = bmi(person.height_cm, person.weight_kg)

    values = {
        "BMI reference indicator": round(bmi_indicator(person_bmi), 1),
        "Blood-pressure indicator": round(
            blood_pressure_indicator(
                person.systolic_bp,
                person.diastolic_bp
            ),
            1,
        ),
        "A1C indicator": round(a1c_indicator(person.a1c_percent), 1),
        "Smoking-status indicator": round(
            smoking_indicator(person.smoker),
            1,
        ),
        "Data-completeness indicator": round(
            data_completeness_indicator(person),
            1,
        ),
    }

    # Equal weights: 20% each.
    illustrative_average = round(sum(values.values()) / len(values), 1)

    reasons = []

    if values["BMI reference indicator"] < 75:
        reasons.append("BMI is outside the selected reference interval.")

    if values["Blood-pressure indicator"] < 80:
        reasons.append("Blood pressure may warrant repeat measurement or review.")

    if values["A1C indicator"] < 100:
        reasons.append("A1C may warrant discussion with a healthcare professional.")

    if person.smoker:
        reasons.append("Smoking status may warrant preventive counseling.")

    if values["Data-completeness indicator"] < 100:
        reasons.append("Some input data is incomplete.")

    return {
        "name": person.name,
        "bmi": round(person_bmi, 1),
        "indicators": values,
        "illustrative_average": illustrative_average,
        "reasons": reasons,
    }


def print_result(result: dict) -> None:
    print("=" * 60)
    print(result["name"])
    print("=" * 60)
    print(f"BMI: {result['bmi']}")
    print()

    for label, value in result["indicators"].items():
        print(f"{label}: {value}/100")

    print()
    print(f"Illustrative average: {result['illustrative_average']}/100")
    print()
    print("Interpretation:")
    print("  This is an educational demonstration only.")
    print("  It is not an insurance, surgical, medication, or treatment decision.")

    if result["reasons"]:
        print()
        print("Possible discussion points:")
        for reason in result["reasons"]:
            print(f"  - {reason}")

    print()


people = [
    Person(
        name="Alex Example",
        age=29,
        height_cm=178,
        weight_kg=76,
        smoker=False,
        systolic_bp=118,
        diastolic_bp=76,
        a1c_percent=5.2,
        chronic_conditions=[],
    ),
    Person(
        name="Morgan Sample",
        age=54,
        height_cm=165,
        weight_kg=102,
        smoker=True,
        systolic_bp=148,
        diastolic_bp=94,
        a1c_percent=6.1,
        chronic_conditions=["hypertension"],
    ),
    Person(
        name="Taylor Demo",
        age=67,
        height_cm=172,
        weight_kg=70,
        smoker=False,
        systolic_bp=132,
        diastolic_bp=82,
        a1c_percent=7.0,
        chronic_conditions=["type 2 diabetes"],
    ),
]


for person in people:
    print_result(evaluate(person))

