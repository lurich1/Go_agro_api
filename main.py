import os
import base64
from fastapi import FastAPI, Form, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
import re # For simple text parsing

# Load environment variables from .env file
load_dotenv()

# OpenRouter API setup
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY") # Your OpenRouter API key here
)
MODEL = "openai/gpt-4o" # Using gpt-4o as a powerful general model

# FastAPI app initialization
app = FastAPI(
    title="SmartFarm AI API (Livestock & Crops)",
    description="API for AI-powered livestock health monitoring, crop disease detection, and resource recommendations."
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_methods=["*"],
    allow_credentials=True,
    allow_headers=["*"],
    allow_origins=["*"],
)

# --- In-memory Mock Data for Resources (for MVP) ---
# In a production system, this would be fetched from a database or a dedicated service.

# Livestock-specific resources
AGRO_OFFICES = [
    {"id": "AO001", "name": "Green Pastures Vet Clinic", "address": "123 Farm Rd, Rural Town", "contact": "555-1234", "services": ["vet consultation", "vaccines", "diagnostics"]},
    {"id": "AO002", "name": "FarmCare Agro Services", "address": "456 Market St, Agri-City", "contact": "555-5678", "services": ["feed supplements", "equipment rental", "basic vet advice"]},
    {"id": "AO003", "name": "Livestock Aid Center", "address": "789 Country Lane, Village A", "contact": "555-9012", "services": ["emergency vet", "medication sales"]},
]

DRUG_STORES = [
    {"id": "DS001", "name": "Animal Health Pharmacy", "address": "101 Vet Blvd, Rural Town", "contact": "555-1122", "drugs_available": ["antibiotics", "dewormers", "vitamins", "pain relievers"]},
    {"id": "DS002", "name": "Rural Farm Meds", "address": "202 Main St, Agri-City", "contact": "555-3344", "drugs_available": ["pain relievers", "anti-inflammatories", "wound care", "vaccines"]},
]

# Crop-specific resources
AGRI_SUPPLY_STORES = [
    {"id": "ASS001", "name": "Green Thumb Agri-Supplies", "address": "303 Seed Ln, Farmville", "contact": "555-6001", "products": ["pesticides", "fungicides", "herbicides", "fertilizers", "seeds"]},
    {"id": "ASS002", "name": "CropCare Solutions", "address": "404 Harvest Rd, Agri-City", "contact": "555-6002", "products": ["organic pesticides", "soil testing kits", "irrigation equipment", "specialty fertilizers"]},
    {"id": "ASS003", "name": "Farmer's Friend Store", "address": "505 Plough St, Village B", "contact": "555-6003", "products": ["general pesticides", "fungicides", "insecticides", "weed killers"]},
]

# --- Helper functions to find resources based on keywords ---
def find_nearby_livestock_resources(keywords: list[str]):
    found_agro_offices = []
    found_drug_stores = []

    for keyword in keywords:
        for office in AGRO_OFFICES:
            if keyword.lower() in " ".join(office["services"]).lower() or keyword.lower() in office["name"].lower():
                if office not in found_agro_offices:
                    found_agro_offices.append(office)
        for store in DRUG_STORES:
            if keyword.lower() in " ".join(store["drugs_available"]).lower() or keyword.lower() in store["name"].lower():
                if store not in found_drug_stores:
                    found_drug_stores.append(store)
    return found_agro_offices, found_drug_stores

def find_nearby_crop_resources(keywords: list[str]):
    found_agri_supply_stores = []

    for keyword in keywords:
        for store in AGRI_SUPPLY_STORES:
            if keyword.lower() in " ".join(store["products"]).lower() or keyword.lower() in store["name"].lower():
                if store not in found_agri_supply_stores:
                    found_agri_supply_stores.append(store)
    return found_agri_supply_stores

# --- Response Models ---
class LivestockDiagnosisResponse(BaseModel):
    diagnosis: str
    recommended_treatment: str
    agro_offices: list[dict]
    drug_stores: list[dict]

class LivestockBotResponse(BaseModel):
    response: str

class LivestockHealthInsightsResponse(BaseModel):
    insights: str

class CropDiagnosisResponse(BaseModel):
    diagnosis: str
    recommended_treatment: str
    agri_supply_stores: list[dict]

class CropBotResponse(BaseModel):
    response: str

# --- AI Functions ---

# --- Livestock AI Functions ---
def analyze_livestock_image(image_base64: str) -> str:
    """
    Uses AI to analyze an image of a sick animal or symptoms and provide a diagnosis and treatment.
    Accepts image as base64 string.
    """
    messages = [
        {
            "role": "system",
            "content": "You are a helpful livestock veterinarian AI that provides preliminary diagnoses and general treatment suggestions based on images of sick animals or symptoms. Your advice is for informational purposes and does not replace professional veterinary consultation."
        },
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Analyze the condition of the livestock shown in this image. Provide a likely diagnosis and a general recommendation for treatment or next steps. Be concise and focus on common livestock diseases. Example output: 'Diagnosis: Foot-and-mouth disease. Recommendation: Isolate animal, consult vet, consider antiviral medication.'"},
                {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_base64}"}} # Assuming JPEG, adjust if needed
            ]
        }
    ]
    
    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=0.0,
    )
    return response.choices[0].message.content

def generate_livestock_bot_response(user_input: str) -> str:
    """
    Provides general advice and information about livestock health and husbandry.
    """
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "You are an agriculture expert chatbot that provides advice and information to farmers about livestock health, breeding, nutrition, and general animal husbandry only. Do not respond to anything outside the context of livestock farming."
            },
            {
                "role": "user",
                "content": user_input
            }
        ],
        temperature=0.0,
    )
    return response.choices[0].message.content

def generate_sensor_insights(temperature: float, activity_level: int, feeding_pattern: str) -> str:
    """
    Generates AI insights based on livestock sensor data.
    """
    prompt = f"Analyze the following livestock sensor data: Temperature: {temperature}°C, Activity Level: {activity_level} units, Feeding Pattern: {feeding_pattern}. " \
             "Provide insights into the animal's health and suggest any potential concerns or recommendations. " \
             "Focus on common health indicators and actionable advice."
    
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "You are an AI assistant specialized in livestock health monitoring. You analyze sensor data to provide insights and recommendations for animal well-being."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.0,
    )
    return response.choices[0].message.content

# --- Crop AI Functions ---
def analyze_crop_image(image_base64: str) -> str:
    """
    Uses AI to analyze an image of a crop leaf/plant and provide a diagnosis and treatment.
    Accepts image as base64 string.
    """
    messages = [
        {
            "role": "system",
            "content": "You are a helpful crop plant doctor AI that provides preliminary diagnoses and general treatment suggestions based on images of crop leaves or plants. Your advice is for informational purposes and does not replace professional agricultural consultation."
        },
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Analyze the condition of this crop leaf/plant from the image. Provide a likely diagnosis of the disease or deficiency and a general recommendation for treatment or next steps. Be concise and focus on common crop diseases/issues. Example output: 'Diagnosis: Early Blight. Recommendation: Apply a copper-based fungicide, improve air circulation.'"},
                {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_base64}"}} # Assuming JPEG, adjust if needed
            ]
        }
    ]
    
    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=0.0,
    )
    return response.choices[0].message.content

def generate_crop_bot_response(user_input: str) -> str:
    """
    Provides general advice and information about crop farming.
    """
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "You are an agriculture expert chatbot that provides advice and information to farmers about crop farming, including planting, pest control, fertilization, and harvesting. Do not respond to anything outside the context of crop farming."
            },
            {
                "role": "user",
                "content": user_input
            }
        ],
        temperature=0.0,
    )
    return response.choices[0].message.content

# --- FastAPI Endpoints ---

# --- Livestock Endpoints ---
@app.post("/diagnose-livestock-image", response_model=LivestockDiagnosisResponse)
async def diagnose_livestock_image_endpoint(file: UploadFile = File(...)):
    """
    Analyzes a livestock image uploaded by the user using AI and provides diagnosis, treatment, and nearby resource recommendations.
    Accepts image file via multipart/form-data.
    """
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only images are allowed.")

    image_bytes = await file.read()
    image_base64 = base64.b64encode(image_bytes).decode("utf-8")

    ai_response_text = analyze_livestock_image(image_base64)

    # Simple parsing of AI response for MVP to extract keywords for resources
    diagnosis_match = re.search(r"Diagnosis:\s*(.*?)(?=\.\s*Recommendation:|$)", ai_response_text, re.IGNORECASE)
    diagnosis = diagnosis_match.group(1).strip() if diagnosis_match else "Undetermined"

    recommendation_match = re.search(r"Recommendation:\s*(.*)", ai_response_text, re.IGNORECASE)
    recommended_treatment = recommendation_match.group(1).strip() if recommendation_match else ai_response_text

    # Extract keywords for resource lookup (e.g., "vet", "medication", "vaccine")
    keywords = []
    if "vet" in recommended_treatment.lower() or "veterinarian" in recommended_treatment.lower() or "consult" in recommended_treatment.lower():
        keywords.append("vet consultation")
    if "medication" in recommended_treatment.lower() or "drug" in recommended_treatment.lower() or "antibiotic" in recommended_treatment.lower() or "dewormer" in recommended_treatment.lower() or "vitamin" in recommended_treatment.lower():
        keywords.append("medication")
        keywords.append("antibiotics") # Specific drug type
        keywords.append("dewormers")
        keywords.append("vitamins")
    if "vaccine" in recommended_treatment.lower():
        keywords.append("vaccines")
    if "feed" in recommended_treatment.lower() or "nutrition" in recommended_treatment.lower() or "supplement" in recommended_treatment.lower():
        keywords.append("feed supplements")

    # Add diagnosis keywords for more specific resource lookup
    if "foot-and-mouth" in diagnosis.lower():
        keywords.append("foot-and-mouth") # If specific drugs are available for this
    # Add more disease-specific keywords as needed

    agro_offices, drug_stores = find_nearby_livestock_resources(keywords)

    return JSONResponse(content={
        "diagnosis": diagnosis,
        "recommended_treatment": recommended_treatment,
        "agro_offices": agro_offices,
        "drug_stores": drug_stores,
    })

@app.post("/livestock-chat", response_model=LivestockBotResponse)
async def livestock_chat_endpoint(query: str = Form(...)):
    """
    Engages in a chat about general livestock health and husbandry.
    """
    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
    
    chatbot_response = generate_livestock_bot_response(query)
    return JSONResponse(content={"response": chatbot_response})

@app.post("/livestock-sensor-insights", response_model=LivestockHealthInsightsResponse)
async def livestock_sensor_insights_endpoint(
    temperature: float = Form(...),
    activity_level: int = Form(...),
    feeding_pattern: str = Form(...),
):
    """
    Provides AI insights and recommendations based on livestock sensor data.
    """
    insights = generate_sensor_insights(temperature, activity_level, feeding_pattern)
    return JSONResponse(content={"insights": insights})

# --- Crop Endpoints ---
@app.post("/diagnose-crop-image", response_model=CropDiagnosisResponse)
async def diagnose_crop_image_endpoint(file: UploadFile = File(...)):
    """
    Analyzes a crop leaf/plant image uploaded by the user using AI and provides diagnosis, treatment, and nearby agri-supply store recommendations.
    Accepts image file via multipart/form-data.
    """
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only images are allowed.")

    image_bytes = await file.read()
    image_base64 = base64.b64encode(image_bytes).decode("utf-8")

    ai_response_text = analyze_crop_image(image_base64)

    # Simple parsing of AI response for MVP to extract keywords for resources
    diagnosis_match = re.search(r"Diagnosis:\s*(.*?)(?=\.\s*Recommendation:|$)", ai_response_text, re.IGNORECASE)
    diagnosis = diagnosis_match.group(1).strip() if diagnosis_match else "Undetermined"

    recommendation_match = re.search(r"Recommendation:\s*(.*)", ai_response_text, re.IGNORECASE)
    recommended_treatment = recommendation_match.group(1).strip() if recommendation_match else ai_response_text

    # Extract keywords for resource lookup (e.g., "fungicide", "pesticide", "fertilizer")
    keywords = []
    if "fungicide" in recommended_treatment.lower():
        keywords.append("fungicides")
    if "pesticide" in recommended_treatment.lower() or "insecticide" in recommended_treatment.lower() or "pest control" in recommended_treatment.lower():
        keywords.append("pesticides")
        keywords.append("insecticides")
    if "herbicide" in recommended_treatment.lower() or "weed" in recommended_treatment.lower():
        keywords.append("herbicides")
        keywords.append("weed killers")
    if "fertilizer" in recommended_treatment.lower() or "nutrient" in recommended_treatment.lower():
        keywords.append("fertilizers")
        keywords.append("specialty fertilizers")
    if "seed" in recommended_treatment.lower() or "planting" in recommended_treatment.lower():
        keywords.append("seeds")
    if "soil" in recommended_treatment.lower():
        keywords.append("soil testing kits")

    # Add diagnosis keywords for more specific resource lookup
    if "blight" in diagnosis.lower() or "rust" in diagnosis.lower():
        keywords.append("fungicides")
    if "aphids" in diagnosis.lower() or "mites" in diagnosis.lower():
        keywords.append("pesticides")
    # Add more disease-specific keywords as needed

    agri_supply_stores = find_nearby_crop_resources(keywords)

    return JSONResponse(content={
        "diagnosis": diagnosis,
        "recommended_treatment": recommended_treatment,
        "agri_supply_stores": agri_supply_stores,
    })

@app.post("/crop-chat", response_model=CropBotResponse)
async def crop_chat_endpoint(query: str = Form(...)):
    """
    Engages in a chat about general crop farming.
    """
    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty.")
    
    chatbot_response = generate_crop_bot_response(query)
    return JSONResponse(content={"response": chatbot_response})

# --- Root endpoint for health check ---
@app.get("/")
async def read_root():
    return {"message": "SmartFarm AI API (Livestock & Crops) is running!"}
