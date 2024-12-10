from fastapi import FastAPI, File, UploadFile, status, Request
from starlette.responses import RedirectResponse, JSONResponse
import os
import tempfile
import lightgbm as lgb
import logging
import pefile

import ember
from config import settings
import utils

app_desc = """<h2> Malware Detection of Portable Executable (PE) file"""
app = FastAPI(description = app_desc)

logger = logging.getLogger('uvicorn.error')

if not os.path.exists(settings.MODEL_PATH):
    logger.error(f"Ember model {settings.MODEL_PATH} does not exist")
lgbm_model = lgb.Booster(model_file=settings.MODEL_PATH)

unit = 'B'
if settings.MAX_FILE_SIZE > utils.SIZE_UNIT_TABLE['GB']+1:
    unit = 'GB'
elif settings.MAX_FILE_SIZE > utils.SIZE_UNIT_TABLE['MB']+1:
    unit = 'MB'
else:
    unit = 'KB'
file_too_large_message = f"File too large. Size of uploaded file must be less than {utils.convert_size(settings.MAX_FILE_SIZE, in_unit='B', out_unit=unit)} {unit}"


@app.middleware("http")
async def validate_file_size(request: Request, call_next):
    content_length = request.headers.get('content-length')
    if content_length and int(content_length) > settings.MAX_FILE_SIZE:
        content_length = int(content_length)


        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                'status': 'failed',
                'data': {
                    'message': file_too_large_message
                }
            }
        )

    return await call_next(request)

@app.get("/",include_in_schema=False)
async def index():
	return RedirectResponse(url="/docs")

@app.post("/detect", description="Upload PE file and detect malware in it")
async def parse(file: UploadFile = File(...)):
    extension = os.path.splitext(file.filename)[1]
    _, path = tempfile.mkstemp(prefix='parser_', suffix=extension, dir='uploaded_file')

    with open(path, 'ab') as f:
        chunk = await file.read(1024*1024)
        while chunk:
            f.write(chunk)
            chunk = await file.read(1024*1024)

    # extract content
    if not os.path.exists(path):
        logger.error(f"{path} does not exist")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            content={
                'status': 'failed',
                'data': {
                    'message': 'Internal Server Error'                    
                }
            }
        )

    with open(path, 'rb') as f:
        file_data = f.read()

        # Check if the uploaded file is a valid PE file
        try:
            pe = pefile.PE(data=file_data)
        except pefile.PEFormatError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    'status': 'failed',
                    'data': {
                        'message': 'Invalid file format. Not a PE file.'
                    }
                }
            )
        finally:
            # remove temp file
            os.remove(path)
        
        score = ember.predict_sample(lgbm_model, file_data, settings.FEATURE_VERSION)

    if score > settings.THRESHOLD:
        message = 'Your file is potentially a malware'
    else:
        message = 'Your file is not a malware'

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            'status': 'success',
            'data': {
                'message': message,
                'prediction': score
            }
        }
    )

