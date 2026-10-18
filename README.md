# 🔐 HealthChain – Secure Healthcare Management System

A blockchain-based healthcare application designed to protect medical records through encryption, digital signatures, and blockchain-based integrity verification.

## 🚀 Features

- 🔑 **Secure Authentication** – Role-based access for patients, doctors, and administrators.
- 🏥 **Patient Management** – Patients can manage their healthcare access permissions.
- 👨‍⚕️ **Doctor Module** – Doctors can upload and access authorized medical records.
- 🔒 **Data Encryption** – Protects sensitive healthcare information.
- ✍️ **Digital Signatures** – Supports verification of record authenticity.
- ⛓️ **Blockchain Integrity** – Uses a custom blockchain to maintain record integrity.
- 📊 **Admin Dashboard** – Provides administrative access and monitoring.
- 🔗 **Ethereum Integration** – Optional integration with Ganache for blockchain anchoring.

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Database | MySQL |
| Blockchain | Custom Blockchain |
| Encryption | Fernet |
| Digital Signatures | RSA |
| Hashing | SHA-256 |
| Smart Contract Testing | Ganache |
| Frontend | HTML, CSS, JavaScript |

## 📁 Project Structure

```text
HealthChain-Secure-Healthcare/
├── app.py
├── blockchain.py
├── ethereum_anchor.py
├── security.py
├── requirements.txt
├── .env.example
├── .gitignore
├── templates/
├── static/
└── README.md
```

## ⚙️ Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/VaishnaviSuresh57/HealthChain-Secure-Healthcare.git
cd HealthChain-Secure-Healthcare
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the database

- Install and start MySQL.
- Create the database named `healthchain` if your application does not create it automatically.
- Copy `.env.example` to `.env`.
- Configure your database connection and required secret values in `.env`.

**Never upload `.env`, encryption keys, or real patient records to GitHub.**

### 5. Run the application

```bash
python app.py
```

Open your browser at:

```text
http://127.0.0.1:5000
```

## 🔐 Security Considerations

- Encrypt sensitive medical data.
- Verify digital signatures and blockchain integrity.
- Enforce authorization checks for protected operations.
- Keep secret keys and database credentials outside the public repository.
- Use HTTPS and secure configuration for production deployment.

## 📸 Screenshots

Add screenshots of the login page, patient dashboard, doctor module, and admin dashboard here.

## 👩‍💻 Developed By

**Vaishnavi S.**

Computer Science and Engineering  
HealthChain – Secure Healthcare Management System

---

*Academic project focused on healthcare data security, access control, and blockchain-based integrity.*
