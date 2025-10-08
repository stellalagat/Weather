// server.js - Enhanced SkyWatch Backend with World Map Features
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
require('dotenv').config();

// Initialize Express app
const app = express();

// Environment variables
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/skywatch';
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key_here_make_it_very_long_and_secure';
const WEATHER_API_KEY = process.env.WEATHER_API_KEY || 'abab777a3e74af7fe8b45dc8958d4493';
const OPENWEATHER_API_KEY = WEATHER_API_KEY; // Using the same API key

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200 // Increased limit for map features
});
app.use(limiter);

// Middleware
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// MongoDB Connection
mongoose.connect(MONGODB_URI)
    .then(() => console.log('MongoDB Connected Successfully'))
    .catch(err => {
        console.error('MongoDB Connection Error:', err);
        process.exit(1);
    });

// User Schema and Model
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: 6
    },
    location: {
        type: String,
        default: 'New York'
    },
    preferences: {
        units: {
            type: String,
            enum: ['metric', 'imperial'],
            default: 'imperial'
        },
        mapLayers: {
            type: [String],
            default: ['temperature', 'precipitation']
        }
    }
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Get user initials for avatar
userSchema.methods.getInitials = function() {
    return this.name
        .split(' ')
        .map(n => n[0])
        .join('')
        .toUpperCase();
};

const User = mongoose.model('User', userSchema);

// Weather Data Schema and Model
const weatherDataSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    city: {
        type: String,
        required: true
    },
    coordinates: {
        lat: Number,
        lng: Number
    },
    current: {
        temp: Number,
        humidity: Number,
        wind: Number,
        uv: Number,
        pressure: Number,
        rainChance: Number,
        condition: String,
        scoreBadge: String,
        icon: String
    },
    hourlyForecast: [{
        time: String,
        temp: Number,
        condition: String,
        wind: Number,
        humidity: Number
    }],
    historicalData: {
        temperatures: [Number],
        precipitation: [Number],
        windSpeed: [Number],
        humidity: [Number],
        airQuality: [Number],
        pressure: [Number]
    }
}, {
    timestamps: true
});

// Create index for faster queries
weatherDataSchema.index({ userId: 1, city: 1 });
weatherDataSchema.index({ coordinates: '2dsphere' });

const WeatherData = mongoose.model('WeatherData', weatherDataSchema);

// Map Session Schema for tracking user map interactions
const mapSessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    viewport: {
        center: {
            lat: Number,
            lng: Number
        },
        zoom: Number
    },
    activeLayers: [String],
    lastActive: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

const MapSession = mongoose.model('MapSession', mapSessionSchema);

// Authentication Middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'No token provided, authorization denied' 
            });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Token is not valid' 
            });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(401).json({ 
            success: false, 
            message: 'Token is not valid' 
        });
    }
};

// Generate JWT Token
const generateToken = (userId) => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '30d' });
};

// Weather API Configuration
const WEATHER_BASE_URL = 'https://api.openweathermap.org/data/2.5';

// Helper function to get weather icon based on condition
const getWeatherIcon = (condition, isDay = true) => {
    const icons = {
        'Clear': isDay ? 'sun' : 'moon',
        'Clouds': 'cloud',
        'Rain': 'cloud-rain',
        'Drizzle': 'cloud-drizzle',
        'Thunderstorm': 'bolt',
        'Snow': 'snowflake',
        'Mist': 'smog',
        'Smoke': 'smog',
        'Haze': 'smog',
        'Dust': 'smog',
        'Fog': 'smog',
        'Sand': 'smog',
        'Ash': 'smog',
        'Squall': 'wind',
        'Tornado': 'tornado'
    };
    return icons[condition] || 'cloud';
};

// Helper function to generate mock historical data
const generateHistoricalData = () => {
    return {
        temperatures: Array.from({ length: 12 }, () => Math.floor(Math.random() * 40) + 40), // 40-80°F
        precipitation: [30, 15, 5, 50], // Rain, Snow, Hail, None percentages
        windSpeed: Array.from({ length: 12 }, () => Math.floor(Math.random() * 20) + 5), // 5-25 mph
        humidity: Array.from({ length: 12 }, () => Math.floor(Math.random() * 40) + 40), // 40-80%
        airQuality: Array.from({ length: 6 }, () => Math.floor(Math.random() * 100) + 50), // 50-150 AQI
        pressure: Array.from({ length: 12 }, () => Math.floor(Math.random() * 100) + 1000) // 1000-1100 hPa
    };
};

// Helper function to generate hourly forecast
const generateHourlyForecast = (currentTemp, condition) => {
    const hours = [];
    const now = new Date();
    
    for (let i = 0; i < 12; i++) {
        const hourTime = new Date(now.getTime() + (i * 60 * 60 * 1000));
        const hourString = hourTime.getHours().toString().padStart(2, '0') + ':00';
        
        // Temperature fluctuates around current temp
        const tempVariation = Math.floor(Math.random() * 6) - 3; // -3 to +3 variation
        const hourTemp = currentTemp + tempVariation;
        
        // Wind and humidity variations
        const windVariation = Math.floor(Math.random() * 4) - 2; // -2 to +2 variation
        const baseWind = Math.floor(Math.random() * 15) + 5; // 5-20 mph base
        const hourWind = Math.max(0, baseWind + windVariation);
        
        const humidityVariation = Math.floor(Math.random() * 10) - 5; // -5 to +5 variation
        const baseHumidity = Math.floor(Math.random() * 30) + 40; // 40-70% base
        const hourHumidity = Math.max(20, Math.min(90, baseHumidity + humidityVariation));
        
        hours.push({
            time: hourString,
            temp: hourTemp,
            condition: condition,
            wind: hourWind,
            humidity: hourHumidity
        });
    }
    
    return hours;
};

// Helper function to get temperature score badge
const getTemperatureScore = (temp) => {
    if (temp >= 80) return 'Hot';
    if (temp >= 70) return 'Warm';
    if (temp >= 60) return 'Mild';
    if (temp >= 50) return 'Cool';
    if (temp >= 40) return 'Chilly';
    return 'Cold';
};

// Helper function to get storm intensity
const getStormIntensity = (windSpeed) => {
    if (windSpeed >= 74) return 'high'; // Hurricane force
    if (windSpeed >= 39) return 'medium'; // Gale force
    return 'low'; // Tropical storm
};

// Helper function to get storm category
const getStormCategory = (windSpeed) => {
    if (windSpeed >= 157) return 'Category 5';
    if (windSpeed >= 130) return 'Category 4';
    if (windSpeed >= 111) return 'Category 3';
    if (windSpeed >= 96) return 'Category 2';
    if (windSpeed >= 74) return 'Category 1';
    return 'Tropical Storm';
};

// ==================== ROUTES ====================

// Health check route
app.get('/api/health', (req, res) => {
    res.json({ 
        success: true, 
        message: 'SkyWatch API is running', 
        timestamp: new Date().toISOString() 
    });
});

// ==================== AUTH ROUTES ====================

// Register user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists with this email'
            });
        }

        // Create new user
        const user = new User({
            name,
            email,
            password
        });

        await user.save();

        // Generate token
        const token = generateToken(user._id);

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                initials: user.getInitials(),
                location: user.location,
                preferences: user.preferences
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during registration'
        });
    }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check password
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Generate token
        const token = generateToken(user._id);

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                initials: user.getInitials(),
                location: user.location,
                preferences: user.preferences
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login'
        });
    }
});

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
    try {
        res.json({
            success: true,
            user: {
                id: req.user._id,
                name: req.user.name,
                email: req.user.email,
                initials: req.user.getInitials(),
                location: req.user.location,
                preferences: req.user.preferences
            }
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Update user preferences
app.put('/api/auth/preferences', auth, async (req, res) => {
    try {
        const { location, units, mapLayers } = req.body;
        
        const updateData = {};
        if (location) updateData.location = location;
        if (units) updateData['preferences.units'] = units;
        if (mapLayers) updateData['preferences.mapLayers'] = mapLayers;

        const user = await User.findByIdAndUpdate(
            req.user._id,
            updateData,
            { new: true }
        ).select('-password');

        res.json({
            success: true,
            message: 'Preferences updated successfully',
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                initials: user.getInitials(),
                location: user.location,
                preferences: user.preferences
            }
        });

    } catch (error) {
        console.error('Update preferences error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error updating preferences'
        });
    }
});

// ==================== WEATHER ROUTES ====================

// Get weather data for user's default location
app.get('/api/weather', auth, async (req, res) => {
    try {
        const city = req.user.location || 'New York';
        
        // Fetch current weather from OpenWeatherMap API
        const response = await axios.get(`${WEATHER_BASE_URL}/weather`, {
            params: {
                q: city,
                appid: OPENWEATHER_API_KEY,
                units: 'imperial'
            }
        });

        const weatherData = response.data;
        
        // Extract current conditions
        const current = {
            temp: Math.round(weatherData.main.temp),
            humidity: weatherData.main.humidity,
            wind: Math.round(weatherData.wind.speed),
            uv: Math.floor(Math.random() * 11), // Mock UV index (0-10)
            pressure: weatherData.main.pressure,
            rainChance: Math.floor(Math.random() * 100), // Mock rain chance
            condition: weatherData.weather[0].main,
            scoreBadge: getTemperatureScore(Math.round(weatherData.main.temp)),
            icon: getWeatherIcon(weatherData.weather[0].main)
        };

        // Generate forecast and historical data
        const hourlyForecast = generateHourlyForecast(current.temp, current.condition);
        const historicalData = generateHistoricalData();

        // Save to database (optional - for history tracking)
        const weatherRecord = new WeatherData({
            userId: req.user._id,
            city: city,
            coordinates: {
                lat: weatherData.coord.lat,
                lng: weatherData.coord.lon
            },
            current: current,
            hourlyForecast: hourlyForecast,
            historicalData: historicalData
        });

        await weatherRecord.save();

        res.json({
            success: true,
            city: city,
            current: current,
            hourlyForecast: hourlyForecast,
            historicalData: historicalData
        });

    } catch (error) {
        console.error('Weather data fetch error:', error);
        
        // Fallback to mock data if API fails
        const mockCurrent = {
            temp: 72,
            humidity: 65,
            wind: 12,
            uv: 5,
            pressure: 1013,
            rainChance: 30,
            condition: 'Clear',
            scoreBadge: 'Mild',
            icon: 'sun'
        };

        const hourlyForecast = generateHourlyForecast(mockCurrent.temp, mockCurrent.condition);
        const historicalData = generateHistoricalData();

        res.json({
            success: true,
            city: req.user.location || 'New York',
            current: mockCurrent,
            hourlyForecast: hourlyForecast,
            historicalData: historicalData
        });
    }
});

// Get weather data for specific city
app.get('/api/weather/:city', auth, async (req, res) => {
    try {
        const city = req.params.city;
        
        // Fetch current weather from OpenWeatherMap API
        const response = await axios.get(`${WEATHER_BASE_URL}/weather`, {
            params: {
                q: city,
                appid: OPENWEATHER_API_KEY,
                units: 'imperial'
            }
        });

        const weatherData = response.data;
        
        // Extract current conditions
        const current = {
            temp: Math.round(weatherData.main.temp),
            humidity: weatherData.main.humidity,
            wind: Math.round(weatherData.wind.speed),
            uv: Math.floor(Math.random() * 11), // Mock UV index (0-10)
            pressure: weatherData.main.pressure,
            rainChance: Math.floor(Math.random() * 100), // Mock rain chance
            condition: weatherData.weather[0].main,
            scoreBadge: getTemperatureScore(Math.round(weatherData.main.temp)),
            icon: getWeatherIcon(weatherData.weather[0].main)
        };

        // Generate forecast and historical data
        const hourlyForecast = generateHourlyForecast(current.temp, current.condition);
        const historicalData = generateHistoricalData();

        // Save to database
        const weatherRecord = new WeatherData({
            userId: req.user._id,
            city: city,
            coordinates: {
                lat: weatherData.coord.lat,
                lng: weatherData.coord.lon
            },
            current: current,
            hourlyForecast: hourlyForecast,
            historicalData: historicalData
        });

        await weatherRecord.save();

        res.json({
            success: true,
            city: city,
            current: current,
            hourlyForecast: hourlyForecast,
            historicalData: historicalData
        });

    } catch (error) {
        console.error('City weather fetch error:', error);
        
        if (error.response?.status === 404) {
            return res.status(404).json({
                success: false,
                message: 'City not found'
            });
        }

        // Fallback to mock data
        const mockCurrent = {
            temp: 68,
            humidity: 60,
            wind: 10,
            uv: 4,
            pressure: 1015,
            rainChance: 25,
            condition: 'Clouds',
            scoreBadge: 'Mild',
            icon: 'cloud'
        };

        const hourlyForecast = generateHourlyForecast(mockCurrent.temp, mockCurrent.condition);
        const historicalData = generateHistoricalData();

        res.json({
            success: true,
            city: req.params.city,
            current: mockCurrent,
            hourlyForecast: hourlyForecast,
            historicalData: historicalData
        });
    }
});

// ==================== WORLD MAP ROUTES ====================

// Get weather data for multiple cities (for map markers)
app.get('/api/map/cities', auth, async (req, res) => {
    try {
        const majorCities = [
            { name: 'New York', lat: 40.7128, lng: -74.0060 },
            { name: 'London', lat: 51.5074, lng: -0.1278 },
            { name: 'Tokyo', lat: 35.6762, lng: 139.6503 },
            { name: 'Moscow', lat: 55.7558, lng: 37.6173 },
            { name: 'Beijing', lat: 39.9042, lng: 116.4074 },
            { name: 'Sydney', lat: -33.8688, lng: 151.2093 },
            { name: 'São Paulo', lat: -23.5505, lng: -46.6333 },
            { name: 'New Delhi', lat: 28.6139, lng: 77.2090 },
            { name: 'Cairo', lat: 30.0444, lng: 31.2357 },
            { name: 'Mexico City', lat: 19.4326, lng: -99.1332 }
        ];

        const citiesWithWeather = await Promise.all(
            majorCities.map(async (city) => {
                try {
                    const response = await axios.get(`${WEATHER_BASE_URL}/weather`, {
                        params: {
                            lat: city.lat,
                            lon: city.lng,
                            appid: OPENWEATHER_API_KEY,
                            units: 'imperial'
                        }
                    });

                    const weatherData = response.data;
                    
                    return {
                        name: city.name,
                        lat: city.lat,
                        lng: city.lng,
                        temp: Math.round(weatherData.main.temp),
                        condition: weatherData.weather[0].main,
                        humidity: weatherData.main.humidity,
                        wind: Math.round(weatherData.wind.speed),
                        pressure: weatherData.main.pressure,
                        icon: getWeatherIcon(weatherData.weather[0].main)
                    };
                } catch (error) {
                    console.error(`Error fetching weather for ${city.name}:`, error);
                    // Return mock data if API fails
                    return {
                        name: city.name,
                        lat: city.lat,
                        lng: city.lng,
                        temp: Math.floor(Math.random() * 40) + 40,
                        condition: 'Clear',
                        humidity: Math.floor(Math.random() * 50) + 30,
                        wind: Math.floor(Math.random() * 20) + 5,
                        pressure: 1013,
                        icon: 'sun'
                    };
                }
            })
        );

        res.json({
            success: true,
            cities: citiesWithWeather
        });

    } catch (error) {
        console.error('Map cities error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching map cities data'
        });
    }
});

// Get global weather statistics
app.get('/api/map/global-stats', auth, async (req, res) => {
    try {
        // In a real implementation, you would aggregate data from multiple sources
        // For now, we'll generate realistic mock data
        
        const globalStats = {
            avgTemperature: 24.7,
            activeStorms: 7,
            cloudCover: 42,
            avgPressure: 1013,
            hottestPlace: {
                name: 'Death Valley, USA',
                temp: 42
            },
            coldestPlace: {
                name: 'Vostok Station, Antarctica',
                temp: -58
            },
            wettestPlace: {
                name: 'Mawsynram, India',
                rainfall: 287
            }
        };

        res.json({
            success: true,
            stats: globalStats
        });

    } catch (error) {
        console.error('Global stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching global statistics'
        });
    }
});

// Get storm data (tropical cyclones, hurricanes, etc.)
app.get('/api/map/storms', auth, async (req, res) => {
    try {
        // Note: Real storm data would require a specialized API
        // For demonstration, we'll create realistic mock storm data
        
        const storms = [
            {
                name: 'Hurricane Elena',
                lat: 25.0,
                lng: -60.0,
                windSpeed: 115,
                category: getStormCategory(115),
                intensity: getStormIntensity(115),
                pressure: 945,
                movement: 'NW at 12 mph'
            },
            {
                name: 'Typhoon Haishen',
                lat: 18.0,
                lng: 140.0,
                windSpeed: 140,
                category: getStormCategory(140),
                intensity: getStormIntensity(140),
                pressure: 920,
                movement: 'N at 10 mph'
            },
            {
                name: 'Cyclone Burevi',
                lat: 10.0,
                lng: 75.0,
                windSpeed: 95,
                category: getStormCategory(95),
                intensity: getStormIntensity(95),
                pressure: 970,
                movement: 'W at 8 mph'
            }
        ];

        res.json({
            success: true,
            storms: storms
        });

    } catch (error) {
        console.error('Storms data error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching storm data'
        });
    }
});

// Get weather data by coordinates
app.get('/api/map/coordinates', auth, async (req, res) => {
    try {
        const { lat, lng } = req.query;
        
        if (!lat || !lng) {
            return res.status(400).json({
                success: false,
                message: 'Latitude and longitude are required'
            });
        }

        const response = await axios.get(`${WEATHER_BASE_URL}/weather`, {
            params: {
                lat: parseFloat(lat),
                lon: parseFloat(lng),
                appid: OPENWEATHER_API_KEY,
                units: 'imperial'
            }
        });

        const weatherData = response.data;
        
        const weatherInfo = {
            name: weatherData.name,
            lat: weatherData.coord.lat,
            lng: weatherData.coord.lon,
            temp: Math.round(weatherData.main.temp),
            condition: weatherData.weather[0].main,
            description: weatherData.weather[0].description,
            humidity: weatherData.main.humidity,
            wind: Math.round(weatherData.wind.speed),
            pressure: weatherData.main.pressure,
            icon: getWeatherIcon(weatherData.weather[0].main)
        };

        res.json({
            success: true,
            weather: weatherInfo
        });

    } catch (error) {
        console.error('Coordinates weather error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching weather for coordinates'
        });
    }
});

// Save map session (viewport, layers, etc.)
app.post('/api/map/session', auth, async (req, res) => {
    try {
        const { viewport, activeLayers } = req.body;
        
        // Update or create map session
        await MapSession.findOneAndUpdate(
            { userId: req.user._id },
            {
                viewport,
                activeLayers,
                lastActive: new Date()
            },
            { upsert: true, new: true }
        );

        res.json({
            success: true,
            message: 'Map session saved successfully'
        });

    } catch (error) {
        console.error('Save map session error:', error);
        res.status(500).json({
            success: false,
            message: 'Error saving map session'
        });
    }
});

// Get user's map session
app.get('/api/map/session', auth, async (req, res) => {
    try {
        const mapSession = await MapSession.findOne({ userId: req.user._id });
        
        res.json({
            success: true,
            session: mapSession || null
        });

    } catch (error) {
        console.error('Get map session error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching map session'
        });
    }
});

// Get weather history for user
app.get('/api/weather/history/recent', auth, async (req, res) => {
    try {
        const recentSearches = await WeatherData.find({ userId: req.user._id })
            .sort({ createdAt: -1 })
            .limit(10)
            .select('city current createdAt');
        
        res.json({
            success: true,
            recentSearches
        });
    } catch (error) {
        console.error('Weather history error:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching weather history'
        });
    }
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'API endpoint not found'
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`SkyWatch server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`MongoDB: ${MONGODB_URI}`);
    console.log(`Weather API Key: ${OPENWEATHER_API_KEY ? 'Configured' : 'Missing'}`);
    console.log('World Map Features: Enabled');
    console.log('Available Endpoints:');
    console.log('  GET  /api/health');
    console.log('  POST /api/auth/register');
    console.log('  POST /api/auth/login');
    console.log('  GET  /api/auth/me');
    console.log('  PUT  /api/auth/preferences');
    console.log('  GET  /api/weather');
    console.log('  GET  /api/weather/:city');
    console.log('  GET  /api/map/cities');
    console.log('  GET  /api/map/global-stats');
    console.log('  GET  /api/map/storms');
    console.log('  GET  /api/map/coordinates');
    console.log('  POST /api/map/session');
    console.log('  GET  /api/map/session');
});