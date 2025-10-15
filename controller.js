import password_samples from "./password_samples.js";

const minus_pattern = /[a-z]/;
const mayus_pattern = /[A-Z]/;
const number_pattern = /\d/;
const special_pattern = /[!"#$%&/()=?'¿¡~*`{}_-]/;

function check_entropy_level(E) {
  if (E <= 60) return "débil";
  if (E <= 80) return "fuerte";
  return "muy fuerte";
}

/**
 * @param {"number" | "minus" | "mayus" | "special"} type
 * @param {string} password
 */
function has(type, password) {
  let result = false;
  switch (type) {
    case "special":
      result = special_pattern.test(password);
      break;
    case "number":
      result = number_pattern.test(password);
      break;
    case "mayus":
      result = mayus_pattern.test(password);
      break;
    case "minus":
      result = minus_pattern.test(password);
      break;
    default:
      throw new Error("tipo no permitido");
  }
  return result ? 1 : 0;
}

/**
 * @param {import("express").Request} req
 * @param {import("express").Response} res
 */
export function checkPassword(req, res) {
  /** @type {{password: string}} */
  const { password } = req.body;
  const password_length = password.length;
  const keyspace =
    has("minus", password) +
    has("mayus", password) +
    has("number", password) +
    has("special", password);
  if (keyspace === 0 || password_length === 0) {
    return res.status(400).json({
      success: false,
      message: "Contraseña vacía o inválida"
    });
  }
  const entropy = password_length * Math.log2(keyspace);
  const entropy_level = check_entropy_level(entropy);
  const near_samples = is_in_any_sample(password, 0.5);
  return res.status(200).json({
    success: true,
    message: `tienes una contraseña ${entropy_level}`,
    password_level: entropy_level,
    contraseñas_similares: near_samples.length === 0 ? "ninguna" : `encontramos ${near_samples.length} contraseñas similares a la tuya en diccionarios de contraseñas comunes`,
    contraseñas_parecidas: near_samples
  });
}

/**
 * @param {string} password
 * @param {number} percemptage 
 */
function is_in_any_sample(password, percemptage) {
  /**
   * @type {Array<{password: string, rank: string, ocurrences: number}>}
   */
  const signed_samples = password_samples.map(s => ({ ...s, ocurrences: 0 }));
  for (const sample of signed_samples) {
    sample.ocurrences = 0;
  }
  for (let i = 0; i < password.length; i++) {
    const char = password[i];
    for (const sample of signed_samples) {
      if (sample.password.length > i) {
        if (sample.password.charAt(i) === char) {
          sample.ocurrences++;
        }
      }
    }
  }
  const near_samples = [];
  for (const sample of signed_samples) {
    const max_length = Math.max(password.length, sample.password.length);
    const near_per = sample.ocurrences / max_length;
    if (near_per >= percemptage) {
      sample.parecido = `${(near_per * 100).toFixed(2)}%`;
      near_samples.push(sample);
    }
  }
  return near_samples;
}