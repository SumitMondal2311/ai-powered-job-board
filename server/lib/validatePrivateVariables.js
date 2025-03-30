const validatePrivateVariables = () => {
  const privateVariables = [
    "FRONTEND_URL",
    "DATABASE_URL",
    "NODE_ENV",
    "UPSTASH_REDIS_REST_URL",
    "UPSTASH_REDIS_REST_TOKEN",
    "ACCESS_TOKEN_SECRET",
    "REFRESH_TOKEN_SECRET",
  ];

  const missingPrivateVariables = privateVariables.filter(
    (key) => !process.env[key]
  );

  if (missingPrivateVariables.length > 0) {
    throw new Error(
      `Missing private variables: ${missingPrivateVariables.join(", ")}`
    );
  }
};

export default validatePrivateVariables;
