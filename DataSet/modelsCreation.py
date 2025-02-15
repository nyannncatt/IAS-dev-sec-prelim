import pandas as pd
import matplotlib.pyplot as plt
import pickle
from sklearn import preprocessing
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split


df = pd.read_csv('newdata.csv')

x = df.drop(['Attack Type'], axis=1)
y = df['Attack Type']

category_col = ['protocol_type', 'flag']
labelEncoder = LabelEncoder()
for col in category_col:
    x[col] = labelEncoder.fit_transform(x[col])

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

# Random Forest Model
rf_model = RandomForestClassifier()
rf_model.fit(x_train, y_train)
rf_accuracy = rf_model.score(x_test, y_test)
print(f"Model Accuracy: {rf_accuracy}")
with open('random_forest_model.pkl', 'wb') as model_file:
    pickle.dump(rf_model, model_file)
print("Model saved as random_forest_model.pkl")


# Protocol Type Label Encoder
label_encoder_protocol_type = LabelEncoder()
df['protocol_type_encoded'] = label_encoder_protocol_type.fit_transform(df['protocol_type'])
with open('ML Models/protocol_type_label_encoder.pkl', 'wb') as le_file:
    pickle.dump(label_encoder_protocol_type, le_file)
print("Protocol Type Label Encoder File has saved.")



# Flag Label Encoder
label_encoder_flag = LabelEncoder()
df['flag_encoded'] = label_encoder_flag.fit_transform(df['flag'])
with open('ML Models/flag_label_encoder.pkl', 'wb') as le_file:
    pickle.dump(label_encoder_flag, le_file)
print("Flag Label Encoder File has saved.")