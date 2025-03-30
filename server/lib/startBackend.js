import prisma from "../configs/prisma.js";

const PORT = process.env.PORT || 5000;

const startBackend = async (app) => {
  try {
    await prisma.$connect();
    console.log("🔗 Prisma connected to Database");

    app.listen(PORT, async () => {
      console.log(`🚀 Server is ready on http://localhost:${PORT}`);
    });
  } catch (error) {
    await prisma.$disconnect();
    console.error("Prisma connection failed: " + error);
    process.exit(1);
  }
};

export default startBackend;
