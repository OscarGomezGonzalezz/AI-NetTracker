import pandas as pd
from sklearn.preprocessing import StandardScaler

# Cargar el archivo CSV
df = pd.read_csv("data/network_traffic.csv")

# Llenar valores faltantes
df.fillna(0, inplace=True)

# Seleccionar las características que usaremos
features = [
    "Src Packet Count", "Dst Packet Count",
    "Src Byte Count", "Dst Byte Count",
    "Src Port Count", "Dst Port Count",
    "Src Length StdDev", "Dst Length StdDev", "Length", "Protocol"
]

# Normalizar los datos
scaler = StandardScaler()
features_scaled = scaler.fit_transform(df[features])

# Guardar los datos preprocesados para el modelo
df_scaled = pd.DataFrame(features_scaled, columns=features)
df_scaled.to_csv("data/preprocessed_network_traffic.csv", index=False)
