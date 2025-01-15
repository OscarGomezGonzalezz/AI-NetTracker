from sklearn.ensemble import IsolationForest
import pandas as pd

# Cargar los datos preprocesados
df = pd.read_csv("data/preprocessed_network_traffic.csv")

# Crear y entrenar el modelo de Isolation Forest
model = IsolationForest(contamination=0.05, random_state=42)#we stimate the 5% of the traffic is malicious

#train the model
model.fit(df)

#After training the model, we predict if each packet is normal(1) or malicious(-1)
df["Anomaly"] = model.predict(df)

# Guardar resultados con anomalías marcadas
df.to_csv("data/anomalies_detected.csv", index=False)
