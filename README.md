# PhishShield

**A Secure Browser Extension Powered by LLMs for Real-Time Phishing Detection in URLs and Emails**

---

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Setup and Installation](#setup-and-installation)
- [Usage](#usage)
- [Datasets](#datasets)
- [Training Models](#training-models)
- [Running the Backend API](#running-the-backend-api)
- [Loading the Chrome Extension](#loading-the-chrome-extension)
- [Challenges](#challenges)
- [Future Work](#future-work)
- [Contributing](#contributing)
- [License](#license)

---

## Project Overview

PhishShield is a final-year project that aims to provide a real-time, evidence-based phishing detection tool via a **browser extension**. It uses **DistilBERT-based models** for classifying phishing URLs and suspicious sentences inside emails or webpage content, providing users with actionable visual alerts and explanations.

---

## Features

- **Real-time URL phishing detection** using optimized DistilBERT.
- **Suspicious sentence highlighting** in email or web content to indicate risky phrases.
- **Evidence-based tooltips** explaining why content is flagged.
- **User behavior logging** for adaptive feedback.
- Lightweight and easy-to-use Chrome/Edge browser extension.
- Modular backend API built with FastAPI for ML inference.

---

## Architecture
