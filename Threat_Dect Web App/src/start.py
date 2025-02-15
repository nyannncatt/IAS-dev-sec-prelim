import pickle
import pandas as pd
from flask import Flask, jsonify
from flask_cors import CORS
from sklearn.impute import SimpleImputer

app = Flask(__name__)
CORS(app)

def read_timestamps(timestamp_file):
    with open(timestamp_file, 'r') as file:
        timestamps = file.readlines()
    return timestamps

@app.route("/results", methods=['GET'])
def results():
    try:
        # Read input data from CSV file
        input_data = pd.read_csv('D:/TechtonicShift/Pcap/captured_packets.csv')

        # Impute missing values
        imputer = SimpleImputer(strategy='most_frequent')
        input_data = pd.DataFrame(imputer.fit_transform(input_data), columns=input_data.columns)

        # Load your trained machine learning model
        rf = pickle.load(open('ML Models/random_forest_model.pkl', 'rb'))

        # Load label encoders
        label_encoders = {}
        categorical_cols = ['protocol_type', 'flag']
        for col in categorical_cols:
            label_encoders[col] = pickle.load(open(f'ML Models/{col}_label_encoder.pkl', 'rb'))

        # Transform categorical features
        for col in categorical_cols:
            input_data[col] = label_encoders[col].transform(input_data[col])

        # Perform prediction
        rf_prediction = rf.predict(input_data)

        # Read timestamps from file
        timestamps = read_timestamps('D:/TechtonicShift/Pcap/packet_timestamps.txt')

        # Return predictions and timestamps as JSON data
        return jsonify(rf_prediction=rf_prediction.tolist(), timestamps=timestamps)
    except Exception as e:
        return jsonify(error=str(e))

if __name__ == "__main__":
    app.run(debug=True)
