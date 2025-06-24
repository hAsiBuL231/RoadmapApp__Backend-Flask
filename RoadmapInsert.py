from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

# Setup database connection - modify this for your database
DATABASE_URI = 'sqlite:///roadmap.db'  # Using SQLite for simplicity
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)
db = Session()

# Define the model
Base = declarative_base()

class RoadmapItem(Base):
    __tablename__ = 'roadmap_item'
    
    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    status = Column(String(50), nullable=False)
    upvotes = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

# Create tables if they don't exist
Base.metadata.create_all(engine)

# Sample data
sample_items = [
    {
        'title': 'Dark Mode Implementation',
        'description': 'Add a dark theme option to reduce eye strain and improve battery life on OLED devices.',
        'status': 'Under Review',
        'upvotes': 42,
        'created_at': datetime.now(timezone.utc) - timedelta(days=10)
    },
    {
        'title': 'Mobile App Redesign',
        'description': 'Complete UI overhaul to improve usability on mobile devices with modern design principles.',
        'status': 'In Progress',
        'upvotes': 89,
        'created_at': datetime.now(timezone.utc) - timedelta(days=5)
    },
    {
        'title': 'Two-Factor Authentication',
        'description': 'Implement 2FA for enhanced account security using TOTP and SMS options.',
        'status': 'Planned',
        'upvotes': 156,
        'created_at': datetime.now(timezone.utc) - timedelta(days=3)
    },
    {
        'title': 'API Rate Limiting',
        'description': 'Add rate limiting to public API endpoints to prevent abuse.',
        'status': 'Completed',
        'upvotes': 27,
        'created_at': datetime.now(timezone.utc) - timedelta(days=15)
    },
    {
        'title': 'User Profile Customization',
        'description': 'Allow users to customize their profiles with avatars, bios, and social links.',
        'status': 'Under Review',
        'upvotes': 63,
        'created_at': datetime.now(timezone.utc) - timedelta(days=1)
    }
]

def create_sample_data():
    try:
        # Clear existing data (optional)
        db.query(RoadmapItem).delete()
        
        # Add new sample data
        for item_data in sample_items:
            item = RoadmapItem(**item_data)
            db.add(item)
        
        db.commit()
        print(f"Successfully inserted {len(sample_items)} sample roadmap items!")
    except Exception as e:
        db.rollback()
        print(f"Error occurred: {e}")
    finally:
        db.close()

if __name__ == '__main__':
    create_sample_data()