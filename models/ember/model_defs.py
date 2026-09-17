"""Model architecture builders — identical to training notebook Cell 39.
Must be used to reconstruct models BEFORE loading .weights.h5 files.
"""
import tensorflow as tf
from tensorflow.keras import layers, Model


def build_autoencoder(input_dim, encoding_dim):
    ae_input = layers.Input(shape=(input_dim,))
    encoded = layers.Dense(max(16, input_dim // 4), activation="relu")(ae_input)
    encoded = layers.Dense(encoding_dim, activation="relu")(encoded)
    decoded = layers.Dense(max(16, input_dim // 4), activation="relu")(encoded)
    decoded = layers.Dense(input_dim, activation="linear")(decoded)
    model = Model(ae_input, decoded, name="deep_autoencoder")
    model.compile(optimizer="adam", loss="mse")
    return model


def build_block_lstm_model(n_features, blocks, embed_dim, lstm_units):
    inp = layers.Input(shape=(n_features,), name="flat_features")
    block_embeddings = []
    for name, start, end in blocks:
        sliced = layers.Lambda(
            lambda x, s=start, e=end: x[:, s:e],
            output_shape=(end - start,),
            name=f"slice_{name}"
        )(inp)
        emb = layers.Dense(embed_dim, activation="relu", name=f"embed_{name}")(sliced)
        block_embeddings.append(emb)

    seq = layers.Lambda(
        lambda ts: tf.stack(ts, axis=1),
        output_shape=(len(block_embeddings), embed_dim),
        name="stack_blocks"
    )(block_embeddings)

    x = layers.Bidirectional(layers.LSTM(lstm_units, return_sequences=True))(seq)
    x = layers.Dropout(0.3)(x)
    x = layers.Bidirectional(layers.LSTM(max(8, lstm_units // 2)))(x)
    x = layers.Dropout(0.3)(x)
    x = layers.Dense(32, activation="relu")(x)
    out = layers.Dense(1, activation="sigmoid")(x)

    model = Model(inp, out, name="structural_block_bilstm")
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model
