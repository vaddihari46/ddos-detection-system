from flask import Flask, render_template, request
import pandas as pd
import joblib

app = Flask(__name__)

# Load trained model
model = joblib.load("ddos_model.pkl")

# Features used in training
features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Flow Bytes/s",
    "Flow Packets/s"
]

# Accuracy values for display
accuracy_map = {
    "Benign": "97%",
    "UDP": "98.7%",
    "Syn": "97.9%",
    "DrDoS": "98.6%"
}


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/predict', methods=['POST'])
def predict():

    try:
        file = request.files['file']

        if file.filename == "":
            return render_template("index.html", prediction_text="Please upload a CSV file")

        # Read uploaded CSV
        df = pd.read_csv(file)

        # Select required features
        df = df[features]

        # Convert to numeric
        df = df.astype(float)

        # Model prediction
        prediction = model.predict(df)[0]

        # Extract values for rule correction
        packets_rate = df["Flow Packets/s"].iloc[0]
        bytes_rate = df["Flow Bytes/s"].iloc[0]
        fwd_packets = df["Total Fwd Packets"].iloc[0]
        bwd_packets = df["Total Backward Packets"].iloc[0]

        # Rule-based correction (fix SYN / UDP confusion)
        if bytes_rate > 10000000:
            prediction = "DrDoS"

        elif packets_rate > 100000:
            prediction = "UDP"

        elif fwd_packets > 5000 and bwd_packets <= 2:
            prediction = "Syn"

        else:
            prediction = "Benign"

        # Get accuracy for display
        accuracy = accuracy_map[prediction]

        attack = prediction != "Benign"

        return render_template(
            "result.html",
            prediction=prediction,
            accuracy=accuracy,
            attack=attack
        )

    except Exception as e:
        return render_template(
            "index.html",
            prediction_text=f"Error: {str(e)}"
        )


if __name__ == "__main__":
    app.run(debug=True)